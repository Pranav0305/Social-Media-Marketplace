document.addEventListener("DOMContentLoaded", function () {
    const createPostBtn = document.getElementById("createPostBtn");
    if (createPostBtn) {
        createPostBtn.addEventListener("click", function () {
            window.location.href = "/add_post";  // Make sure this route exists
        });
    }
});
