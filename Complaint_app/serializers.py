from account.models import Complaint
from rest_framework import serializers
class ComplaintSerializer(serializers.ModelSerializer):
    user_email = serializers.SerializerMethodField()
    user_role = serializers.SerializerMethodField()
    status_display = serializers.SerializerMethodField()
    can_mark_resolved = serializers.SerializerMethodField()
    responded_by_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Complaint
        fields = [
            'id', 
            'user', 
            'user_email',
            'user_role',
            'description', 
            'status', 
            'status_display',
            'created_at', 
            'updated_at',
            'admin_response',
            'responded_by',
            'responded_by_name',
            'response_date',
            'client_feedback',
            'resolution_rating',
            'feedback_date',
            'can_mark_resolved'
        ]
        read_only_fields = [
            'id', 'user', 'user_email', 'user_role', 'created_at', 
            'updated_at', 'status_display', 'can_mark_resolved',
            'responded_by_name', 'response_date', 'feedback_date'
        ]
    
    def get_user_email(self, obj):
        return obj.user.email if obj.user else None
    
    def get_user_role(self, obj):
        return obj.user.role if obj.user else None
    
    def get_status_display(self, obj):
        return obj.get_status_display()
    
    def get_can_mark_resolved(self, obj):
        return obj.can_mark_resolved
    
    def get_responded_by_name(self, obj):
        return obj.responded_by_name
    
    def create(self, validated_data):
        # Associate complaint with the current user
        user = self.context['request'].user
        validated_data['user'] = user
        return super().create(validated_data)

