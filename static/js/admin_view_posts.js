document.addEventListener("DOMContentLoaded", () => {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    let selectedPostId = null;

    const deleteButtons = document.querySelectorAll(".delete-button");
    const otpModal = document.getElementById("otpModal");
    const otpInput = document.getElementById("otpInput");
    const otpStatus = document.getElementById("otpStatusMessage");
    

    deleteButtons.forEach(button => {
        button.addEventListener("click", () => {
            const postId = button.getAttribute("data-post-id");
            selectedPostId = postId;

            // Show "Sending OTP..." message
            otpStatus.textContent = "Sending OTP...";
            otpStatus.style.display = "block";
            otpInput.value = "";
            otpModal.style.display = "block";

            // Call backend to generate OTP
            fetch(`/admin/delete_post_request/${postId}`, {
                method: "GET",
                credentials: "include"
            })
            .then(response => {
                if (!response.ok) throw new Error("Failed to send OTP");
                otpStatus.textContent = "OTP sent to admin email.";
            })
            .catch(error => {
                otpStatus.textContent = "Failed to send OTP.";
                console.error(error);
            });
            

            generateKeyboard();
        });
    });

    document.getElementById("submitOtpBtn").addEventListener("click", submitOtp);
    document.getElementById("cancelOtpBtn").addEventListener("click", closeOtpModal);

    function closeOtpModal() {
        otpModal.style.display = "none";
        selectedPostId = null;
        otpStatus.style.display = "none";
    }

    function submitOtp() {
        const otp = otpInput.value;
        if (otp.length !== 6) {
            alert("Please enter a 6-digit OTP.");
            return;
        }

        fetch("/admin/verify_delete_post", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrfToken
            },
            credentials: "include",
            body: JSON.stringify({
                otp: otp,
                post_id: selectedPostId
            })
        })
        .then(async res => {
            if (!res.ok) {
                const text = await res.text();
                throw new Error(`HTTP ${res.status}: ${text}`);
            }
            return res.json();
        })        
        .then(data => {
            if (data.success) {
                document.getElementById(`post-${selectedPostId}`).remove();
                closeOtpModal();
            } else {
                alert(data.message || "Invalid OTP.");
            }
        })
        .catch(err => {
            console.error("Error:", err);
            alert("Something went wrong.");
        });
    }

    function generateKeyboard() {
        const container = document.getElementById("virtualKeyboard");
        container.innerHTML = "";
        const digits = Array.from({ length: 10 }, (_, i) => i.toString()).sort(() => Math.random() - 0.5);
        for (const digit of digits) {
            const btn = document.createElement("button");
            btn.className = "key";
            btn.textContent = digit;
            btn.onclick = () => {
                if (otpInput.value.length < 6) {
                    otpInput.value += digit;
                }
            };
            container.appendChild(btn);
        }
    }
});
