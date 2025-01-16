document.addEventListener("DOMContentLoaded", () => {
    const authToken = localStorage.getItem("authToken");

    // Функция загрузки данных профиля
    async function loadProfile() {
        try {
            const response = await fetch("/profile", {
                method: "GET",
                headers: {
                    "Authorization": `Bearer ${authToken}`,
                    "Content-Type": "application/json",
                },
            });

            if (response.ok) {
                const data = await response.json();
                console.log(data); // Проверьте, что данные загружаются

                // Установка значений
                document.getElementById("account-name").textContent = data.name || "Not available";
                document.getElementById("account-email").textContent = data.email || "Not available";
                document.getElementById("account-role").textContent = data.role || "User";

                // Отображение фото
                const profilePicture = document.getElementById("profile-picture-preview");
                profilePicture.src = data.picture || "default-profile.png";
            } else {
                console.error("Failed to load profile:", await response.text());
            }
        } catch (err) {
            console.error("Error loading profile:", err);
        }
    }


    // Функция для обновления профиля
    async function updateProfile() {
        const name = document.getElementById("name").value.trim();
        const email = document.getElementById("email").value.trim();
        const profilePicture = document.getElementById("profile-picture").files[0];

        const formData = new FormData();
        if (name) formData.append("name", name);
        if (email) formData.append("email", email);
        if (profilePicture) formData.append("profile_picture", profilePicture);

        try {
            const response = await fetch("/profile/update", {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${authToken}`,
                },
                body: formData,
            });

            if (response.ok) {
                alert("Profile updated successfully!");
                loadProfile();
            } else {
                console.error("Failed to update profile:", await response.text());
            }
        } catch (err) {
            console.error("Error updating profile:", err);
        }
    }

    // Функция смены пароля
    async function changePassword() {
        const oldPassword = document.getElementById("old-password").value.trim();
        const newPassword = document.getElementById("new-password").value.trim();

        if (!oldPassword || !newPassword) {
            alert("Both old and new passwords are required!");
            return;
        }

        try {
            const response = await fetch("/profile/password", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${authToken}`,
                },
                body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
            });

            if (response.ok) {
                alert("Password changed successfully!");
                document.getElementById("password-form").reset();
            } else {
                console.error("Failed to change password:", await response.text());
            }
        } catch (err) {
            console.error("Error changing password:", err);
        }
    }

    // Привязываем обработчики
    document.getElementById("update-profile").addEventListener("click", updateProfile);
    document.getElementById("change-password").addEventListener("click", changePassword);

    // Загружаем данные при открытии
    loadProfile();
});
