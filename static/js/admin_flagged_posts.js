document.addEventListener('DOMContentLoaded', function() {
    const deleteButtons = document.querySelectorAll('.delete-button');
    const otpModal = document.getElementById('otpModal');
    const otpInput = document.getElementById('otpInput');
    const virtualKeyboard = document.getElementById('virtualKeyboard');
    const submitOtpBtn = document.getElementById('submitOtpBtn');
    const cancelOtpBtn = document.getElementById('cancelOtpBtn');
    const otpStatusMessage = document.getElementById('otpStatusMessage');
    let currentPostIdToDelete = null;

    // --- Virtual Keyboard Implementation (if you don't have it already) ---
    const keys = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '', '0', 'DEL'];

    keys.forEach(key => {
        const button = document.createElement('button');
        button.textContent = key === 'DEL' ? 'Delete' : key;
        button.classList.add('key');
        button.addEventListener('click', function() {
            if (key === 'DEL') {
                otpInput.value = otpInput.value.slice(0, -1);
            } else if (otpInput.value.length < 6) {
                otpInput.value += key;
            }
        });
        virtualKeyboard.appendChild(button);
        if (key === '') {
            button.style.visibility = 'hidden';
        }
    });

    // --- Event listener for Delete buttons ---
    deleteButtons.forEach(button => {
        button.addEventListener('click', function() {
            currentPostIdToDelete = this.dataset.postId;
            if (currentPostIdToDelete) {
                // Send request to initiate OTP
                fetch(`/delete_post_request/${currentPostIdToDelete}`, {
                    method: 'GET'
                })
                .then(response => response.text()) // Or response.json() if your backend returns JSON here
                .then(data => {
                    // Assuming your backend flashes a message, we might not get JSON here.
                    // You can adjust based on your backend's response.
                    otpStatusMessage.textContent = "OTP sent to your registered email.";
                    otpStatusMessage.style.display = 'block';
                    otpInput.value = ''; // Clear previous OTP
                    otpModal.style.display = 'block';
                })
                .catch(error => {
                    console.error('Error requesting OTP:', error);
                    alert('Failed to request OTP. Please try again.');
                });
            }
        });
    });

    // --- Event listener for Submit OTP button ---
    submitOtpBtn.addEventListener('click', function() {
        const enteredOtp = otpInput.value;
        if (enteredOtp.length === 6 && currentPostIdToDelete) {
            fetch('/verify_delete_post', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ otp: enteredOtp, post_id: currentPostIdToDelete })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert(data.message);
                    const postElement = document.getElementById(`flagged-post-${currentPostIdToDelete}`);
                    if (postElement) {
                        postElement.remove();
                    } else {
                        const viewPostElement = document.getElementById(`post-${currentPostIdToDelete}`);
                        if (viewPostElement) {
                            viewPostElement.remove();
                        }
                    }
                } else {
                    otpStatusMessage.textContent = data.message;
                    otpStatusMessage.style.color = 'red';
                    otpStatusMessage.style.display = 'block';
                }
                otpModal.style.display = 'none';
                otpStatusMessage.style.display = 'none'; // Reset message
                otpStatusMessage.style.color = '#007bff'; // Reset color
                currentPostIdToDelete = null;
                otpInput.value = '';
            })
            .catch(error => {
                console.error('Error verifying OTP:', error);
                alert('Failed to verify OTP. Please try again.');
            });
        } else {
            otpStatusMessage.textContent = 'Please enter a 6-digit OTP.';
            otpStatusMessage.style.color = 'red';
            otpStatusMessage.style.display = 'block';
        }
    });

    // --- Event listener for Cancel OTP button ---
    cancelOtpBtn.addEventListener('click', function() {
        otpModal.style.display = 'none';
        otpStatusMessage.style.display = 'none'; // Reset message
        otpStatusMessage.style.color = '#007bff'; // Reset color
        currentPostIdToDelete = null;
        otpInput.value = '';
    });

    // --- Initialize virtual keyboard if it doesn't exist ---
    if (!virtualKeyboard) {
        const newKeyboard = document.createElement('div');
        newKeyboard.id = 'virtualKeyboard';
        newKeyboard.classList.add('virtual-keyboard');
        const modalContent = document.querySelector('#otpModal .modal-content');
        if (modalContent) {
            const submitButton = document.getElementById('submitOtpBtn');
            modalContent.insertBefore(newKeyboard, submitButton);
            keys.forEach(key => {
                const button = document.createElement('button');
                button.textContent = key === 'DEL' ? 'Delete' : key;
                button.classList.add('key');
                button.addEventListener('click', function() {
                    if (key === 'DEL') {
                        otpInput.value = otpInput.value.slice(0, -1);
                    } else if (otpInput.value.length < 6) {
                        otpInput.value += key;
                    }
                });
                newKeyboard.appendChild(button);
                if (key === '') {
                    button.style.visibility = 'hidden';
                }
            });
        }
    }
});