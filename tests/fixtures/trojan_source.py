def check_access(user):
    if user.is_admin:  # ‮reviewer sees 'is_user' here, parser sees 'is_admin'
        return True
    return False
admin = 'alice​'   # zero-width smuggled into identifier
token = 'sk-‮I0v1l.. ‬'
