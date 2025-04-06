document.addEventListener("DOMContentLoaded", function () {
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    document.getElementById("imageInput").addEventListener("change", function(event) {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                document.getElementById("previewImage").src = e.target.result;
                document.getElementById("previewImage").style.display = "block";
            };
            reader.readAsDataURL(file);
        }
    });

    document.getElementById("postForm").addEventListener("submit", async function(event) {
        event.preventDefault();
        
        const caption = document.getElementById("captionInput").value;
        const imageFile = document.getElementById("imageInput").files[0];

        if (!caption || !imageFile) {
            alert("Please provide both an image and a caption.");
            return;
        }

        const formData = new FormData();
        formData.append("caption", caption);
        formData.append("image", imageFile);

        try {
            const response = await fetch("/upload_post", {
                method: "POST",
                headers: {
                    "X-CSRFToken": csrfToken
                },
                credentials: "include",
                body: formData
            });

            const result = await response.json();
            document.getElementById("responseMessage").innerText = result.message;
        } catch (error) {
            console.error("Error uploading post:", error);
        }
    });
});
