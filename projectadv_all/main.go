package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt"
	"github.com/sirupsen/logrus"
	"github.com/tebeka/selenium"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

var (
	DB      *gorm.DB
	logger  = logrus.New()
	limiter = rate.NewLimiter(1, 3)
)

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Name     string `gorm:"size:100"`
	Email    string `gorm:"unique"`
	Password string `gorm:"size:255"`
	Role     string `gorm:"default:user"`
	Active   bool   `gorm:"default:true"`
	Verified bool   `gorm:"default:false"`
	Picture  string `gorm:"size:255"`
}

type JSONResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type LogEntry struct {
	ID        uint      `gorm:"primaryKey"`
	Timestamp time.Time `gorm:"autoCreateTime"`
	Level     string    `gorm:"size:20"`
	Message   string
	Fields    string
}

type EmailLog struct {
	ID         uint      `gorm:"primaryKey"`
	Timestamp  time.Time `gorm:"autoCreateTime"`
	Subject    string    `gorm:"size:255"`
	Body       string    `gorm:"type:text"`
	Recipients string    `gorm:"type:text"`
	Status     string    `gorm:"size:50"`
}

func connectDatabase() {
	dsn := "user=postgres password=Dias140506 dbname=mydb2 port=5432 sslmode=disable"
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.Fatal("Failed to connect to database:", err)
	}
	logger.Info("Connected to database successfully")
	DB.AutoMigrate(&User{}, &LogEntry{}, &EmailLog{})
}

type DBHook struct{}

func (hook *DBHook) Fire(entry *logrus.Entry) error {
	fields, _ := json.Marshal(entry.Data)
	logEntry := LogEntry{
		Level:     entry.Level.String(),
		Message:   entry.Message,
		Fields:    string(fields),
		Timestamp: entry.Time,
	}
	if err := DB.Create(&logEntry).Error; err != nil {
		fmt.Println("Failed to save log to database:", err)
	}
	return nil
}

func (hook *DBHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func handleError(w http.ResponseWriter, err error, statusCode int, message string) {
	logger.WithField("error", err).Error(message)
	http.Error(w, message, statusCode)
}

func populateDatabase() {
	logger.Info("Populating database with 50 fake users...")
	for i := 0; i < 50; i++ {
		user := User{
			Name:  gofakeit.Name(),
			Email: gofakeit.Email(),
		}
		if err := DB.Create(&user).Error; err != nil {
			logger.Warn("Error creating user:", err)
		}
	}
	logger.Info("Database populated with 50 fake users.")
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			handleError(w, nil, http.StatusTooManyRequests, "Rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleErrorSimple(w, err, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if err := DB.Create(&user).Error; err != nil {
		handleErrorSimple(w, err, "Failed to create user", http.StatusInternalServerError)
		return
	}

	logger.WithFields(logrus.Fields{"user": user}).Info("User created successfully")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleError(w, err, http.StatusBadRequest, "Invalid request payload")
		return
	}
	var existingUser User
	if err := DB.First(&existingUser, user.ID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			handleError(w, err, http.StatusNotFound, "User not found")
		} else {
			handleError(w, err, http.StatusInternalServerError, "Failed to fetch user")
		}
		return
	}
	existingUser.Name = user.Name
	existingUser.Email = user.Email
	if err := DB.Save(&existingUser).Error; err != nil {
		handleError(w, err, http.StatusInternalServerError, "Failed to update user")
		return
	}
	logger.WithFields(logrus.Fields{"user": user}).Info("User updated successfully")
	json.NewEncoder(w).Encode(existingUser)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleError(w, err, http.StatusBadRequest, "Invalid request payload")
		return
	}
	if err := DB.Delete(&User{}, user.ID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			handleError(w, err, http.StatusNotFound, "User not found")
		} else {
			handleError(w, err, http.StatusInternalServerError, "Failed to delete user")
		}
		return
	}
	logger.WithFields(logrus.Fields{"user_id": user.ID}).Info("User deleted successfully")
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}

func sendEmail(subject, body string, recipients []string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", "diasmendiyarov@mail.ru")
	m.SetHeader("To", recipients...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer("smtp.mail.ru", 587, "diasmendiyarov@mail.ru", "nj6XcauYAkq6yYrktZaS")

	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}
func jsonHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Handling JSON request")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "JSON handler works"})
}
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	var users []User
	query := DB

	// фильтрац
	filter := r.URL.Query().Get("filter")
	if filter != "" {
		query = query.Where("name ILIKE ?", "%"+filter+"%")
		logger.WithFields(logrus.Fields{"filter": filter}).Info("Filtering users by name")
	}

	// сорт
	sort := strings.ToLower(r.URL.Query().Get("sort"))
	validSortFields := map[string]string{
		"name":  "name",
		"email": "email",
	}

	if field, ok := validSortFields[sort]; ok {
		query = query.Order(field)
		logger.WithFields(logrus.Fields{"sort": field}).Info("Sorting users")
	} else if sort != "" {
		logger.Warnf("Invalid sort parameter: %s. Skipping sorting.", sort)
	}

	// пагинация
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit < 1 {
		limit = 10
	}

	offset := (page - 1) * limit
	query = query.Offset(offset).Limit(limit)

	if err := query.Find(&users).Error; err != nil {
		handleErrorSimple(w, err, "Failed to fetch users", http.StatusInternalServerError)
		return
	}

	if len(users) == 0 {
		handleErrorSimple(w, nil, "No users found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func getUserByIDHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var user User
	if err := DB.First(&user, id).Error; err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"message": "User not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
func handleErrorSimple(w http.ResponseWriter, err error, message string, statusCode int) {
	if err != nil {

		logger.WithError(err).Error(message)
	} else {

		logger.Error(message)
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   message,
		"details": err.Error(),
	})
}

func sendEmailHandler(w http.ResponseWriter, r *http.Request) {
	// ограничение 10 мю
	r.ParseMultipartForm(10 << 20)

	subject := r.FormValue("subject")
	body := r.FormValue("body")
	recipients := r.FormValue("recipients")

	recipientList := strings.Split(recipients, ",")

	file, handler, err := r.FormFile("attachment")
	if err != nil {
		logger.WithError(err).Warn("No file uploaded or failed to read file")
		file = nil
	} else {
		defer file.Close()
		logger.WithFields(logrus.Fields{
			"filename": handler.Filename,
			"size":     handler.Size,
		}).Info("File uploaded successfully")
	}

	m := gomail.NewMessage()
	m.SetHeader("From", "diasmendiyarov@mail.ru")
	m.SetHeader("To", recipientList...)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	if file != nil {
		fileBytes, err := io.ReadAll(file)
		if err != nil {
			handleErrorSimple(w, err, "Failed to read uploaded file", http.StatusInternalServerError)
			return
		}
		m.Attach(handler.Filename, gomail.SetCopyFunc(func(w io.Writer) error {
			_, err := w.Write(fileBytes)
			return err
		}))
	}

	d := gomail.NewDialer("smtp.mail.ru", 587, "diasmendiyarov@mail.ru", "nj6XcauYAkq6yYrktZaS")

	if err := d.DialAndSend(m); err != nil {
		handleErrorSimple(w, err, "Failed to send email", http.StatusInternalServerError)
		return
	}

	logger.WithFields(logrus.Fields{
		"subject":    subject,
		"recipients": recipients,
	}).Info("Email sent successfully")

	json.NewEncoder(w).Encode(map[string]string{"message": "Email sent successfully"})
}

func gracefulShutdown(server *http.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown:", err)
	}

	logger.Info("Server exiting")
}

func registerUserHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleErrorSimple(w, err, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Хэширование пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		handleErrorSimple(w, err, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Создание пользователя
	if err := DB.Create(&user).Error; err != nil {
		handleErrorSimple(w, err, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Генерация токена подтверждения
	token := generateVerificationToken(user.Email)

	// Отправка подтверждающего письма
	err = sendEmail(
		"Подтверждение регистрации",
		fmt.Sprintf("Пройдите по ссылке, чтобы подтвердить регистрацию: http://localhost:8080/verify?token=%s", token),
		[]string{user.Email},
	)
	if err != nil {
		handleErrorSimple(w, err, "Failed to send verification email", http.StatusInternalServerError)
		return
	}

	logger.WithField("email", user.Email).Info("Verification email sent")
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully. Please verify your email."})
}

func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем токен из параметра запроса
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Проверяем токен
	email, err := validateVerificationToken(token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	// Обновляем статус пользователя
	if err := DB.Model(&User{}).Where("email = ?", email).Update("verified", true).Error; err != nil {
		http.Error(w, "Failed to verify email", http.StatusInternalServerError)
		return
	}

	// Возвращаем успешный ответ или перенаправляем
	http.Redirect(w, r, "/verification-success.html", http.StatusSeeOther)
}

func generateVerificationToken(email string) string {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret"))
	return tokenString
}

func validateVerificationToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["email"] == nil {
		return "", errors.New("invalid token")
	}
	return claims["email"].(string), nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Поиск пользователя в базе данных
	var user User

	if err := DB.Where("email = ?", creds.Email).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	logger.Info("User login attempt: ", creds.Email)
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		logger.Error("Password mismatch for user: ", creds.Email)
	}

	// Проверка подтверждения email
	if !user.Verified {
		http.Error(w, "Email not verified", http.StatusUnauthorized)
		return
	}

	// Сравнение хэша пароля
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Генерация токена (например, JWT)
	token := generateAuthToken(user.ID, user.Email, user.Role)

	// Ответ на успешный логин
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func generateAuthToken(userID uint, email, role string) string {
	claims := jwt.MapClaims{
		"userID": userID,
		"email":  email,
		"role":   role,
		"exp":    time.Now().Add(24 * time.Hour).Unix(), // Время действия 24 часа
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("secret")) // Используйте тот же "secret"
	return tokenString
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			logger.Error("No token provided")
			http.Error(w, "Unauthorized: Missing token", http.StatusUnauthorized)
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		logger.Infof("Token received: %s", tokenString)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("secret"), nil
		})
		if err != nil || !token.Valid {
			logger.Errorf("Invalid token: %v", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			logger.Error("Invalid claims structure")
			http.Error(w, "Invalid claims", http.StatusUnauthorized)
			return
		}

		logger.Infof("Claims extracted: %v", claims)
		ctx := context.WithValue(r.Context(), "user", claims)
		next(w, r.WithContext(ctx))
	}
}

func roleMiddleware(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userClaims := r.Context().Value("user").(jwt.MapClaims)
		if userClaims["role"] != role {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func adminRoute(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"message": "Welcome, Admin!"})
}

func TestGenerateAuthToken(t *testing.T) {
	token := generateAuthToken(1, "user@example.com", "admin")

	if token == "" {
		t.Error("Token should not be empty")
	}
}

func TestValidateVerificationToken(t *testing.T) {
	email := "user@example.com"
	token := generateVerificationToken(email)

	validatedEmail, err := validateVerificationToken(token)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if validatedEmail != email {
		t.Errorf("Expected %s, got %s", email, validatedEmail)
	}
}

func TestLoginHandler(t *testing.T) {
	// Создаем пользователя для теста
	user := User{
		Name:     "Test User",
		Email:    "test@example.com",
		Password: "password123",
		Role:     "user",
	}
	DB.Create(&user)

	requestBody := `{"email":"test@example.com","password":"password123"}`
	req, _ := http.NewRequest("POST", "/login", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	loginHandler(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.Code)
	}

	var response map[string]string
	json.NewDecoder(resp.Body).Decode(&response)

	if response["token"] == "" {
		t.Error("Expected a token in the response")
	}
}

func TestLoginE2E(t *testing.T) {
	caps := selenium.Capabilities{"browserName": "chrome"}
	wd, err := selenium.NewRemote(caps, "")
	if err != nil {
		t.Fatal(err)
	}
	defer wd.Quit()

	wd.Get("http://localhost:8080/login")
	emailInput, _ := wd.FindElement(selenium.ByID, "email")
	emailInput.SendKeys("test@example.com")
	passwordInput, _ := wd.FindElement(selenium.ByID, "password")
	passwordInput.SendKeys("password123")
	loginButton, _ := wd.FindElement(selenium.ByID, "login-btn")
	loginButton.Click()

	// Проверяем, что пользователь успешно вошел
	welcomeMessage, _ := wd.FindElement(selenium.ByID, "welcome-message")
	text, _ := welcomeMessage.Text()
	if text != "Welcome, Test User!" {
		t.Errorf("Expected welcome message, got %s", text)
	}
}

func TestAuthMiddleware(t *testing.T) {
	// Тестовый обработчик, который использует authMiddleware
	handler := authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		userClaims := r.Context().Value("user").(jwt.MapClaims)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"userID": userClaims["userID"],
			"email":  userClaims["email"],
			"role":   userClaims["role"],
		})
	})

	// Генерируем тестовый токен
	token := generateAuthToken(1, "test@example.com", "user")

	// Создаем запрос с заголовком Authorization
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// Регистрируем обработчик и запускаем сервер
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Проверяем результат
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status OK, got: %v", rr.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	if response["userID"] != float64(1) || response["email"] != "test@example.com" || response["role"] != "user" {
		t.Errorf("Middleware claims extraction failed: %+v", response)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Проверяем уникальность email
	var existingUser User
	if err := DB.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	}

	// Хэшируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Сохраняем пользователя
	if err := DB.Create(&user).Error; err != nil {
		http.Error(w, "Failed to register user", http.StatusInternalServerError)
		return
	}

	// Отправляем подтверждающий email
	token := generateVerificationToken(user.Email)
	err = sendEmail("Email Verification", fmt.Sprintf("Click here to verify: http://localhost:8080/verify?token=%s", token), []string{user.Email})
	if err != nil {
		http.Error(w, "Failed to send verification email", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Registration successful"})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем токен и извлекаем userID из контекста
	userClaims, ok := r.Context().Value("user").(jwt.MapClaims)
	if !ok || userClaims["userID"] == nil {
		http.Error(w, "Unauthorized: Invalid user context", http.StatusUnauthorized)
		return
	}

	userID := uint(userClaims["userID"].(float64))

	// Ищем пользователя в базе данных
	var user User
	if err := DB.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Возвращаем данные профиля пользователя
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":      user.ID,
		"name":    user.Name,
		"email":   user.Email,
		"role":    user.Role,
		"picture": "/static/" + user.Picture, // Добавляем путь к фото
	})
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем токен и извлекаем userID из контекста
	userClaims, ok := r.Context().Value("user").(jwt.MapClaims)
	if !ok || userClaims["userID"] == nil {
		http.Error(w, "Unauthorized: Invalid user context", http.StatusUnauthorized)
		return
	}

	userID := uint(userClaims["userID"].(float64))

	// Ищем пользователя в базе данных
	var user User
	if err := DB.First(&user, userID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Обработка данных формы
	name := r.FormValue("name")
	email := r.FormValue("email")
	role := r.FormValue("role")

	// Обновляем поля профиля, если они переданы
	if name != "" {
		user.Name = name
	}
	if email != "" {
		user.Email = email
	}
	if role != "" {
		user.Role = role
	}

	// Обработка загрузки файла (фото профиля)
	file, header, err := r.FormFile("profile_picture")
	if err == nil { // Если файл передан
		defer file.Close()

		// Проверка допустимых расширений
		validExtensions := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true}
		fileExt := filepath.Ext(header.Filename)
		if !validExtensions[fileExt] {
			http.Error(w, "Invalid file type. Only .jpg, .jpeg, .png, .gif are allowed", http.StatusBadRequest)
			return
		}

		// Проверка размера файла (например, не больше 5MB)
		const maxFileSize = 5 * 1024 * 1024 // 5MB
		fileInfo, err := header.Open()
		if err != nil {
			http.Error(w, "Failed to read file", http.StatusInternalServerError)
			return
		}
		defer fileInfo.Close()

		// Проверяем размер файла
		buffer := make([]byte, maxFileSize+1)
		bytesRead, err := fileInfo.Read(buffer)
		if err != nil && err != io.EOF {
			http.Error(w, "Failed to read file size", http.StatusInternalServerError)
			return
		}
		if bytesRead > maxFileSize {
			http.Error(w, "File size exceeds the 5MB limit", http.StatusBadRequest)
			return
		}

		// Генерируем уникальное имя файла
		filePath := fmt.Sprintf("./static/uploads/%d-profile%s", user.ID, fileExt)

		// Сохраняем файл на сервере
		out, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save profile picture", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		// Копируем содержимое файла
		if _, err := io.Copy(out, file); err != nil {
			http.Error(w, "Failed to save profile picture", http.StatusInternalServerError)
			return
		}

		// Сохраняем путь к файлу в базе данных
		user.Picture = strings.TrimPrefix(filePath, "./static/")
	}

	// Сохраняем изменения в базе данных
	if err := DB.Save(&user).Error; err != nil {
		http.Error(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	// Возвращаем успешный ответ, включая обновленные данные
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Profile updated successfully",
		"user": map[string]interface{}{
			"id":      user.ID,
			"name":    user.Name,
			"email":   user.Email,
			"role":    user.Role,
			"picture": fmt.Sprintf("/static/%s", user.Picture),
		},
	})
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	// Логируем начало обработчика
	logger.Info("Starting password change process")

	// Извлечение userID из контекста
	userClaims, ok := r.Context().Value("user").(jwt.MapClaims)
	if !ok || userClaims["userID"] == nil {
		logger.Error("Unauthorized: Invalid user context")
		http.Error(w, "Unauthorized: Invalid user context", http.StatusUnauthorized)
		return
	}
	userID := uint(userClaims["userID"].(float64))
	logger.Infof("Extracted userID: %d", userID)

	// Чтение входных данных
	var input struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		logger.Error("Failed to decode JSON: ", err)
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	logger.Infof("OldPassword: %s, NewPassword: %s", input.OldPassword, input.NewPassword)

	// Поиск пользователя в базе данных
	var user User
	if err := DB.First(&user, userID).Error; err != nil {
		logger.Error("User not found: ", err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	logger.Infof("User found: %v", user)

	// Проверка старого пароля
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.OldPassword)); err != nil {
		logger.Error("Password comparison failed: ", err)
		http.Error(w, "Old password is incorrect", http.StatusUnauthorized)
		return
	}

	// Хэширование нового пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		logger.Error("Failed to hash new password: ", err)
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Обновление пароля в базе данных
	if err := DB.Model(&User{}).Where("id = ?", userID).Update("password", string(hashedPassword)).Error; err != nil {
		logger.Error("Failed to update password: ", err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	logger.Info("Password updated successfully")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password updated successfully"})
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("./templates/" + tmpl + ".html")
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

func navHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем токен
	userClaims, ok := r.Context().Value("user").(jwt.MapClaims)
	var user *User
	if ok {
		// Извлекаем пользователя из базы данных по userID
		var foundUser User
		userID := uint(userClaims["userID"].(float64))
		DB.First(&foundUser, userID)
		user = &foundUser
	}

	// Передаем данные в шаблон
	renderTemplate(w, "index", map[string]interface{}{
		"User": user,
	})
}

func RoleMiddleware(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Извлекаем токен из контекста
			userClaims, ok := r.Context().Value("user").(jwt.MapClaims)
			if !ok || userClaims["userID"] == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			role, _ := userClaims["role"].(string)
			if role != requiredRole {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			// Если роль совпадает, передаем запрос дальше
			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	// Подключение базы данных
	connectDatabase()
	logger.AddHook(&DBHook{})

	// Наполнение базы данных тестовыми данными
	populateDatabase()

	// Настройка логгера
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Регистрация маршрутов
	http.HandleFunc("/json", jsonHandler)

	http.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getUsersHandler(w, r)
		case http.MethodPost:
			createUserHandler(w, r)
		case http.MethodPut:
			updateUserHandler(w, r)
		case http.MethodDelete:
			deleteUserHandler(w, r)
		default:
			handleError(w, nil, http.StatusMethodNotAllowed, "Method not allowed")
		}
	})

	http.HandleFunc("/users/by-id", getUserByIDHandler)
	http.HandleFunc("/admin/send-email", sendEmailHandler)
	http.HandleFunc("/admin/email-logs", getEmailLogsHandler)
	http.HandleFunc("/admin/toggle-user-activation", toggleUserActivationHandler)
	http.HandleFunc("/admin", authMiddleware(roleMiddleware("admin", adminRoute)))
	http.HandleFunc("/profile/update", authMiddleware(updateProfileHandler))    // Обновление профиля
	http.HandleFunc("/profile/password", authMiddleware(changePasswordHandler)) // Смена пароля
	http.HandleFunc("/profile", authMiddleware(profileHandler))                 // Получение профиля
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	http.Handle("/admin", RoleMiddleware("admin")(http.HandlerFunc(adminHandler)))
	http.Handle("/user", RoleMiddleware("user")(http.HandlerFunc(userHandler)))

	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/verify", verifyEmailHandler)

	// Генерация хэшированных паролей (только для примера)
	generateHashedPasswords()

	// Настройка сервера
	server := &http.Server{
		Addr:    ":8080",
		Handler: rateLimitMiddleware(http.DefaultServeMux),
	}

	// Обработка Graceful Shutdown
	go gracefulShutdown(server)

	logger.Info("Server is running on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("ListenAndServe():", err)
	}
	hashedPassword := "$2a$10$KdliJbVdS3lAOGtugsIPSOWIXIJk5iDim0CraQH9jjt2Sy0/hjYBq" // Хэш из базы данных
	inputPassword := "Dias140506"                                                    // Введите предполагаемый пароль

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(inputPassword))
	if err != nil {
		fmt.Println("Пароль неверный:", err)
	} else {
		fmt.Println("Пароль корректный!")
	}

}

// Функция для генерации хэшированных паролей
func generateHashedPasswords() {
	passwords := []string{"password123", "admin123", "user2023"}
	fmt.Println("Generating hashed passwords:")
	for _, password := range passwords {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("Failed to hash password: ", err)
			continue
		}
		fmt.Printf("Original: %s, Hashed: %s\n", password, hashedPassword)
	}
}
func getEmailLogsHandler(w http.ResponseWriter, r *http.Request) {
	var emailLogs []EmailLog
	if err := DB.Order("timestamp desc").Find(&emailLogs).Error; err != nil {
		handleError(w, err, http.StatusInternalServerError, "Failed to fetch email logs")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(emailLogs)
}

func toggleUserActivationHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ID     uint `json:"id"`
		Active bool `json:"active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		handleError(w, err, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var user User
	if err := DB.First(&user, payload.ID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			handleError(w, err, http.StatusNotFound, "User not found")
		} else {
			handleError(w, err, http.StatusInternalServerError, "Failed to fetch user")
		}
		return
	}

	user.Active = payload.Active
	if err := DB.Save(&user).Error; err != nil {
		handleError(w, err, http.StatusInternalServerError, "Failed to update user status")
		return
	}

	action := "deactivated"
	if payload.Active {
		action = "activated"
	}
	logger.WithFields(logrus.Fields{"user_id": user.ID, "active": user.Active}).Infof("User %s", action)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": fmt.Sprintf("User %s successfully", action),
	})

}
