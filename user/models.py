from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.db import models
from django.template.defaultfilters import default
# Create your models here.


class MyUserManager(BaseUserManager):
    def create_user(self, username, password=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """

        user = self.model(username=username)
        user.set_password(password)
        user.save(using=self._db)
        return user



class MyUser(AbstractBaseUser):
    username= models.TextField(unique=True, max_length=12)

    objects = MyUserManager()

    USERNAME_FIELD = 'username'

    def __str__(self):
        return self.username
    
    
    
class IPRecord(models.Model):
    ip=models.GenericIPAddressField()
    failure_times=models.PositiveSmallIntegerField(default=0)
    date_available=models.BigIntegerField(blank=True)
    
    