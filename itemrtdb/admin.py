from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from itemrtdb.models import *

# Admin adminsite

admin.site.register(Topic)
admin.site.register(Type)
admin.site.register(Meta)

admin.site.register(Solution)
admin.site.register(Answer)
admin.site.register(Assessment)
admin.site.register(Response)
admin.site.register(QuestionMeta)
admin.site.register(Test)
admin.site.register(TestResponse)
admin.site.register(TestQuestion)

admin.site.register(QuestionFlag)
admin.site.register(UserUsage)

admin.site.register(Tag)
admin.site.register(QuestionTag)

# Extra fields for Question
class AnswerInline(admin.StackedInline):
    extra = 1
    model = Answer

class SolutionInline(admin.StackedInline):
    extra = 0
    model = Solution

class QuestionAdmin(admin.ModelAdmin):
    inlines = [
        AnswerInline,
        SolutionInline,
    ]

admin.site.register(Question, QuestionAdmin)

# Add User Profile model into User model
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'profile'

# Re-define a User admin
class UserAdmin(UserAdmin):
    inlines = (UserProfileInline, )

# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)