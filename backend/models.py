class User():
    def __init__(self, username, password):
        self.username = username
        self.password = password
    def __str__(self):
        return str(self.username)
    
class Admin():
    def __init__(self, admin_name, admin_password):
        self.admin_name = admin_name
        self.admin_password = admin_password
    def __str__(self):
        return str(self.admin_name)