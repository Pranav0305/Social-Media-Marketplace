document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("registerForm");
    const passwordInput = document.getElementById("password");

    const lengthRule = document.getElementById("length-rule");
    const uppercaseRule = document.getElementById("uppercase-rule");
    const lowercaseRule = document.getElementById("lowercase-rule");
    const numberRule = document.getElementById("number-rule");
    const specialRule = document.getElementById("special-rule");

    // ✅ Real-time password strength feedback
    passwordInput.addEventListener("keyup", function () {
        const password = passwordInput.value;

        lengthRule.style.color = password.length >= 8 ? "green" : "red";
        uppercaseRule.style.color = /[A-Z]/.test(password) ? "green" : "red";
        lowercaseRule.style.color = /[a-z]/.test(password) ? "green" : "red";
        numberRule.style.color = /\d/.test(password) ? "green" : "red";
        specialRule.style.color = /[!@#$%^&*(),.?":{}|<>]/.test(password) ? "green" : "red";
    });

    // ✅ Form submission validation
    form.addEventListener("submit", function (e) {
        const password = passwordInput.value;

        const lengthValid = password.length >= 8;
        const uppercaseValid = /[A-Z]/.test(password);
        const lowercaseValid = /[a-z]/.test(password);
        const numberValid = /\d/.test(password);
        const specialValid = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        if (!lengthValid || !uppercaseValid || !lowercaseValid || !numberValid || !specialValid) {
            alert("Your password does not meet the security requirements.");
            e.preventDefault(); // ❌ Don't submit
        }
    });
});
