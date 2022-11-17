from model import User, db

User.query.all()  # Get all users
User.query.get(2) # Get user where id=2

# Get user where email=fulano@usp.br
user = User.query.filter_by(email='fulano@usp.br').first()

user = User.query.filter_by(email='fulano@usp.br') \
                 .first_or_404(description=f'There is no user with email fulano@usp.br')
