document.getElementById('editProfileForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const form = e.target;
    const formData = new FormData(form);

    // You might need to extract CSRF token from the form manually if needed
    const csrfToken = form.querySelector('input[name="csrf_token"]').value;

    const response = await fetch('/profile/', {
        method: 'POST',
        body: formData,
        headers: {
            'X-CSRFToken': csrfToken  // CSRF token header
        }
    });

    const result = await response.text();
    alert('Profile updated!');
});
