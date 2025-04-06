document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("otpInput");

    input.addEventListener("keydown", e => e.preventDefault());
    input.addEventListener("paste", e => e.preventDefault());

    const digitButtons = document.querySelectorAll(".digit-button");
    digitButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            if (input.value.length < 6) {
                input.value += btn.getAttribute("data-digit");
            }
        });
    });

    const clearBtn = document.getElementById("clearBtn");
    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            input.value = "";
        });
    }

    const backspaceBtn = document.getElementById("backspaceBtn");
    if (backspaceBtn) {
        backspaceBtn.addEventListener("click", () => {
            input.value = input.value.slice(0, -1);
        });
    }
});
