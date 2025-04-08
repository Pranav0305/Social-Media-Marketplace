document.addEventListener("DOMContentLoaded", function () {
    const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content");

    // Approve and Reject functionality
    document.querySelectorAll(".approve-btn, .reject-btn").forEach(button => {
        button.addEventListener("click", function () {
            const userId = this.getAttribute("data-userid");
            const actionUrl = this.getAttribute("data-url");
            const rowId = `user-row-${userId}`;
            const statusCell = document.querySelector(`#${rowId} td[id^='status-']`);
            const actionCell = document.querySelector(`#${rowId} td[id^='action-']`);

            this.disabled = true;

            fetch(actionUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken
                },
                credentials: "include"
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    statusCell.textContent = data.new_status;
                    actionCell.innerHTML = `<strong>${data.new_status.charAt(0).toUpperCase() + data.new_status.slice(1)}</strong>`;
                } else {
                    alert("Error: " + data.error);
                    this.disabled = false;
                }
            })
            .catch(error => {
                console.error("Error:", error);
                alert("An unexpected error occurred.");
                this.disabled = false;
            });
        });
    });

    // Delete functionality for user accounts
    document.querySelectorAll(".delete-btn").forEach(button => {
        button.addEventListener("click", function () {
            const userId = this.getAttribute("data-userid");
            const actionUrl = this.getAttribute("data-url");
            const rowId = `user-row-${userId}`;

            if (confirm("Are you sure you want to delete this user? This action cannot be undone.")) {
                fetch(actionUrl, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": csrfToken
                    },
                    credentials: "include"
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const row = document.getElementById(rowId);
                        if (row) {
                            row.remove();
                        }
                        alert(data.message);
                    } else {
                        alert("Error: " + data.message);
                    }
                })
                .catch(error => {
                    console.error("Error:", error);
                    alert("An unexpected error occurred.");
                });
            }
        });
    });
});
