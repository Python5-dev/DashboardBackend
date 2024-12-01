from django.db import models

class Profile(models.Model):
    username = models.CharField(max_length=100)
    image= models.ImageField(upload_to='images')

    def __str__(self):
        return self.username