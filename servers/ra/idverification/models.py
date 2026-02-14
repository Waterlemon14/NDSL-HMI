from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

# Create your models here.

class Device(models.Model):
    updatedAt = models.DateTimeField(auto_now=True)

    mac = models.CharField(max_length=30, unique=True)
    ip = models.CharField(max_length=30)

    public_key = models.CharField(max_length=130, blank=True, null=True)
    manufacturer = models.TextField(blank=False, null=True)
    csr = models.TextField(blank=True, null=True)
    
    challengeCount = models.SmallIntegerField(default=0)
    interval = models.SmallIntegerField(default=1000000)

    certificate = models.TextField(blank=True, null=True)

class UserManager(BaseUserManager):
    def create_user(self, uin, firstName, lastName):
        if not uin:
            raise ValueError("Users must have a UIN")
        user = self.model(uin=uin, firstName=firstName, lastName=lastName)
        user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, uin, firstName, lastName):
        user = self.create_user(uin, firstName, lastName)
        user.is_admin = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    uin = models.CharField(unique=True, max_length=255)
    firstName = models.TextField(blank=False, null=True)
    lastName = models.TextField(blank=False, null=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    USERNAME_FIELD = 'uin' 
    REQUIRED_FIELDS = ['firstName', 'lastName']

    def __str__(self):
        return self.uin

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True
    
    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin

    def get_full_name(self):
        full_name = f"{self.firstName} {self.lastName}"
        return full_name.strip()
    