from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.utils.timesince import timesince

# New in version 20131023
class Topic(models.Model):
    "Topic model for topics that question can assosicate with"
    name        = models.CharField(max_length=30)
    position    = models.SmallIntegerField(blank=True, null=True)
    #weight      = models.SmallIntegerField(default=1)
    #description = models.CharField(max_length=200)

    class Meta:
        ordering = ['position']

    def __unicode__(self):
        return self.name

# New in version 20131023
# Added description field in version 20131024
class Type(models.Model):
    "Type model for different types of questions"
    name        = models.CharField(max_length=50)
    description = models.CharField(max_length=100)

    def __unicode__(self):
        return self.name

# New in version 20131023
class Meta(models.Model):
    "Meta model to keep the list of meta tags used"
    metatag     = models.CharField(max_length=30, primary_key=True)

    def __unicode__(self):
        return self.metatag

# New in version 20140213
# Manager for Questions showing only the active questions
class ActiveQuestionManager(models.Manager):
    def get_query_set(self):
        return super(ActiveQuestionManager, self).get_query_set().filter(is_active=True)

# New in version 20131023
class Question(models.Model):
    "Question model for MCQ, fill-in-the-blanks questions with 1 part"
    content     = models.TextField(max_length=2000)
    difficulty  = models.IntegerField()
    topic       = models.ForeignKey(Topic)
    time        = models.IntegerField(default=0) # In seconds
    marks       = models.DecimalField(max_digits=3, decimal_places=1, default=1.0)
    type        = models.ForeignKey(Type, default=1)
    meta        = models.ManyToManyField(Meta, through='QuestionMeta')
    is_active   = models.BooleanField(default=True) # Deleted will be false
    tags        = models.ManyToManyField('Tag', through='QuestionTag')

    def _get_question(self):
        "Get text of the question (without choices)"
        index = self.content.find('A.')
        return self.content[0:index]

    def _get_choices(self):
        "Get a tuple of possible choices for the MCQ question"
        # Current code uses simple search and string cutting, TODO: Upgrade to Regex
        indexA = self.content.find('A.')
        indexB = self.content.find('B.')
        indexC = self.content.find('C.')
        indexD = self.content.find('D.')

        indexC = len(self.content) if indexC == -1 else indexC
        indexD = len(self.content) if indexD == -1 else indexD

        # Added +2 to remove the choice lettering (A/B/C/D)
        ans_a = self.content[indexA+2:indexB].strip()
        ans_b = self.content[indexB+2:indexC].strip()
        ans_c = self.content[indexC+2:indexD].strip()
        ans_d = self.content[indexD+2:].strip()

        ans_dict = {}

        if ans_a:
            ans_dict['a'] = ans_a
        if ans_b:
            ans_dict['b'] = ans_b
        if ans_c:
            ans_dict['c'] = ans_c
        if ans_d:
            ans_dict['d'] = ans_d

        return ans_dict

    # Additional property based attributes
    text        = property(_get_question)
    choices     = property(_get_choices)

    # Reimplement default objects manager to filter off questions not active
    objects_all = models.Manager()
    objects     = ActiveQuestionManager()

    class Meta:
        ordering = ['id']

    def __unicode__(self):
        return "Question " + str(self.id)

# New in version 20140214
class Tag(models.Model):
    name        = models.CharField(max_length=30)

    class Meta:
        ordering = ['name']

    def __unicode__(self):
        return str(self.name)

# New in version 20140214
class QuestionTag(models.Model):
    question    = models.ForeignKey(Question)
    tag         = models.ForeignKey(Tag)

# New in version 20131023
class Solution(models.Model):
    "Solution model for question solutions if any"
    question    = models.OneToOneField(Question, primary_key=True, related_name='solution')
    content     = models.TextField(max_length=2000)
    rating      = models.IntegerField(blank=True, null=True)

# New in version 20131023
class Answer(models.Model):
    "Answer model to represent possible answer(s) for question"
    question    = models.ForeignKey(Question, related_name='answers')
    content     = models.TextField(max_length=100)
    correctness = models.DecimalField(max_digits=3, decimal_places=2, default=1) # Ans can be still correct but not 100% correct

# New in version 20131023
class Assessment(models.Model):
    "Assessment model to represent different assessment engines"

    PRACTICE = 'P'
    TEST = 'T'
    ASSESSMENT_MODE_CHOICES = (
        (PRACTICE, 'Practice'),
        (TEST, 'Test'),
    )

    name        = models.CharField(max_length=30)
    type        = models.CharField(max_length=1, choices=ASSESSMENT_MODE_CHOICES)
    active      = models.BooleanField()
    engine      = models.CharField(max_length=30)

    def __unicode__(self):
        return self.name

# New in version 20131023
class Response(models.Model):
    "Response model to store user responses"
    user        = models.ForeignKey(User)
    question    = models.ForeignKey(Question)
    response    = models.TextField(max_length=100)
    date        = models.DateTimeField(auto_now=True)
    duration    = models.IntegerField(blank=True, null=True) # In seconds
    correctness = models.DecimalField(max_digits=3, decimal_places=2, null=True) # Percent correct in dec (0-1)
    criterion   = models.DecimalField(max_digits=3, decimal_places=1) # Max marks for random practice/test, diff for CAT
    ability     = models.DecimalField(max_digits=5, decimal_places=2, null=True) # Current ability score for practices
    assessment  = models.ForeignKey(Assessment)

# New in version 20131208
class Test(models.Model):
    "Test model for storage of each test paper generated"
    STATE_CHOICES = (
        (False, 'Draft'),
        (True, 'Active'),
    )

    id          = models.CharField(max_length=6, primary_key=True) #Unique 6 char alphanumeric ID
    generated   = models.DateTimeField(auto_now=True)
    questions   = models.ManyToManyField(Question, through='TestQuestion')
    assessment  = models.ForeignKey(Assessment)
    state       = models.BooleanField(choices=STATE_CHOICES, default=False)

    def _get_score(self):
        "Gets the score of the completed test"
        question = self.questions.all().reverse()[0] # Get last question

        # Should we filter for users?
        test_response = TestResponse.objects.filter(test=self).filter(question=question)[0]

        return test_response.ability

    score     = property(_get_score)

# New in version 20131208
class TestResponse(Response):
    "TestResponse model for storage of test responses, this links back to the test itself"
    test        = models.ForeignKey(Test, related_name='responses')

    def __unicode__(self):
        return 'TestResponse ' + str(self.id)

# Many to Many intermediary models

# New in version 20131023
class QuestionMeta(models.Model):
    "QuestionMeta model is an intermediary model between Question and Meta models"
    question    = models.ForeignKey(Question)
    meta        = models.ForeignKey(Meta)
    content     = models.CharField(max_length=50)

# New in version 20131208
class TestQuestion(models.Model):
    "TestQuestion model is an intermediary model between Test qnd Question models"
    question    = models.ForeignKey(Question)
    test        = models.ForeignKey(Test)

# New in version 20140205
class UserProfile(models.Model):
    user        = models.OneToOneField(User)

    debug       = models.BooleanField()

    def create_user_profile(sender, instance, created, **kwargs):
        if created:
            UserProfile.objects.create(user=instance)

    post_save.connect(create_user_profile, sender=User)

# New in version 20140215
class UserUsage(models.Model):
    user        = models.ForeignKey(User)
    datetime    = models.DateTimeField(auto_now=True)
    page        = models.CharField(max_length=50)

    class Meta:
        ordering = ['-datetime']

    def __unicode__(self):
        return self.user.get_full_name() + ' last accessed ' + self.page + ' ' + timesince(self.datetime) + ' ago'

# New in version 20140221
class QuestionFlag(models.Model):
    question    = models.ForeignKey(Question)
    user        = models.ForeignKey(User)
    issue       = models.TextField(max_length=2000)
    reported    = models.DateTimeField(auto_now=True)
    resolved    = models.BooleanField(default=False)

