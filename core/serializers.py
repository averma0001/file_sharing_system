from rest_framework import serializers
from .models import User, File
from django.contrib.auth import get_user_model


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'email', 'user_type']
        extra_kwargs = {
            'password': {'write_only': True},  # Ensure password is write-only
        }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['file']
