class UserLogin():

    def fromDB(self, user_id, Users):
        self.__user = Users.query.filter_by(id=user_id).first()
        return self

    def create(self, user):
        self.__user = user
        return self

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.__user.id)

    def get_user(self):
        if self.__user:
            return self.__user
        else:
            return None

