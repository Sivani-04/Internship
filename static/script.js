document.addEventListener("DOMContentLoaded", function() {
    // Handle registration
    var registerButton = document.getElementById('registerButton');
    if (registerButton) {
        registerButton.addEventListener('click', function(event) {
            event.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const team = document.getElementById('team').value;

            fetch('/register-user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password, team })
            })
            .then(response => response.json())
            .then(data => {
                console.log(data);
                window.location.href = '/';
            })
            .catch(error => {
                console.error('Registration failed:', error);
                // Handle error (show error message to user)
            });
        });
    }

    // Handle login
    var loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                console.log(data);
                localStorage.setItem('token', data.token);
                window.location.href = '/dashboard';
            })
            .catch(error => {
                console.error('Sign-in failed:', error);
                // Handle error (show error message to user)
            });
        });
    }

    // Handle create task
    var createTaskButton = document.getElementById('createTaskButton');
    if (createTaskButton) {
        createTaskButton.addEventListener('click', function(event) {
            event.preventDefault();
            window.location.href = '/create';
        });
    }

    // Handle get tasks
    var getTasksButton = document.getElementById('getTasksButton');
    if (getTasksButton) {
            getTasksButton.addEventListener('click', function(event) {
            event.preventDefault();
            window.location.href = '/get-tasks';
        });
    }

    // Handle create task form submission
    var createTaskForm = document.getElementById('createTaskForm');
    if (createTaskForm) {
        createTaskForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const task_name = document.getElementById('task_name').value;
            const task_status = document.getElementById('task_status').value;

            fetch('/create-task', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': localStorage.getItem('token')
                },
                body: JSON.stringify({ task_name, task_status })
            })
            .then(response => response.json())
            .then(data => {
                console.log(data);
                window.location.href = '/dashboard';
                // Handle success (e.g., show success message)
            })
            .catch(error => {
                console.error('Create task failed:', error);
                // Handle error (show error message to user)
            });
        });
    }
});