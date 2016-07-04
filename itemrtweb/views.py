from django.shortcuts import render, render_to_response, redirect
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.template import RequestContext
from django.template.loader import render_to_string

from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from django.contrib.auth.models import User
from django.db.models import Avg

from django.contrib.contenttypes.models import ContentType
from django.contrib.comments.models import Comment

from itemrtdb.models import *
from itemrtproject import assessment_engine, formatter_engine
from itemrtweb import forms

from datetime import datetime, timedelta

import math, re, random, sys

def account_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # Authenticate user w/db
        user = authenticate(username=username, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)
                # Success, check permissions (user/admin)
                if user.is_staff:
                    # Staff redirected to control panel
                    return redirect('/control/')
                else:
                    # User redirected to practice homepage
                    return redirect('/home/')
            else:
                if user.last_login == user.date_joined:
                    # Not activated
                    return render(request, 'auth.login.html', {'error': 'inactive'})
                else:
                    # User account has been disabled
                    return render_to_response('auth.login.html', {'error': 'disabled'}, context_instance=RequestContext(request))
        else:
            # User account not found or password is incorrect
            return render_to_response('auth.login.html', {'error': 'incorrect'}, context_instance=RequestContext(request))
    else:
        if request.user.is_authenticated():
            if 'next' not in request.GET:
                # Why are you visiting my sign in page again?
                return redirect('/')
            else:
                return render(request, 'auth.login.html', {'error':'permission'})
        else:
            return render(request, 'auth.login.html')

def account_logout(request):
    # Logout for user
    logout(request)

    return render_to_response('auth.logout.html', {}, context_instance=RequestContext(request))

def account_register(request):
    if request.method == 'POST':
        form = forms.RegistrationForm(request.POST) # Bind to user submitted form
        if form.is_valid():
            # Process account registration
            user = User.objects.create_user(username=form.cleaned_data['email'], email=form.cleaned_data['email'], password=form.cleaned_data['password'])
            user.first_name=form.cleaned_data['first_name']
            user.last_name=form.cleaned_data['last_name']
            user.is_active = False
            user.save()

            # Generate a activation key using existing salt for pwd
            algorithm, iterations, salt, hashed = user.password.split('$', 3)
            activation_key = make_password(user.email, salt, algorithm)
            algorithm, iterations, salt, activation_key = activation_key.split('$', 3)
            activation_key = activation_key[:-1]
            # Alternative char for + and /
            activation_key = activation_key.replace('+','-').replace('/','_')

            title = 'Account Activation'
            content = render_to_string('register.email', {'first_name': user.first_name, 'last_name': user.last_name, 'is_secure': request.is_secure(), 'host': request.get_host(), 'activation_key': activation_key, 'sender': settings.PROJECT_NAME})

            send_mail(title, content, settings.PROJECT_NAME + ' <' + settings.EMAIL_HOST_USER + '>', [user.email])

            return render(request, 'account.register.success.html')
    else:
        # Display new form for user to fill in
        form = forms.RegistrationForm()

    return render(request, 'account.register.form.html', {'form': form})

def account_activate(request):
    # Already activated
    if request.user.is_authenticated():
        return render(request, 'account.activate.success.html', {'error': 'activated'})

    if request.method == 'GET':
        # Get activation details
        activation_key = request.GET.get('key')

        # No activation key, throw to login page
        if activation_key is None:
            return redirect('/accounts/login/')

        # Keep activation key in session awaiting login
        request.session['activation_key'] = activation_key

        form = forms.ActivationForm()
    else:
        # Attempt to activate user using given user, password and key
        form = forms.ActivationForm(request.POST)
        if form.is_valid():
            # Try logging in
            user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password'])

            if user is None:
                form.activation_error = 'incorrect'
            else:
                # Already active? error!
                if user.is_active:
                    form.activation_error = 'expired'
                else:
                    # Match activation key
                    algorithm, iterations, salt, hashed = user.password.split('$', 3)
                    activation_key = make_password(user.email, salt, algorithm)
                    algorithm, iterations, salt, activation_key = activation_key.split('$', 3)
                    activation_key = activation_key[:-1]
                    # Alternative char for + and /
                    activation_key = activation_key.replace('+','-').replace('/','_')

                    form.key1 = request.session['activation_key']
                    form.key2 = activation_key

                    # Match keys
                    if activation_key == request.session['activation_key']:
                        # Activated, login and proceed
                        user.is_active = True
                        user.save()
                        login(request, user)

                        return render(request, 'account.activate.success.html')
                    else:
                        # Key expired!
                        form.activation_error = 'expired'

    return render(request, 'account.activate.form.html', {'form': form})

def account_forgot(request):
    if request.method == 'POST':
        form = forms.PasswordForgetForm(request.POST) # Bind to user submitted form
        if form.is_valid():
            # Retrieve user from db
            try:
                user = User.objects.get(email=form.cleaned_data['email'])
            except User.DoesNotExist:
                return redirect('/accounts/forgot/?error=nouser')

            # Generate a reset key using existing salt for pwd
            algorithm, iterations, salt, hashed = user.password.split('$', 3)
            reset_key = make_password(user.email, salt, algorithm)
            algorithm, iterations, salt, reset_key = reset_key.split('$', 3)
            reset_key = reset_key[:-1]
            # Alternative char for + and /
            reset_key = reset_key.replace('+','-').replace('/','_')

            title = 'Password Reset'
            content = render_to_string('passwordreset.email', {'first_name': user.first_name, 'last_name': user.last_name, 'host': request.get_host(), 'reset_key': reset_key, 'sender': settings.PROJECT_NAME, 'email': user.email})

            send_mail(title, content, settings.PROJECT_NAME + ' <' + settings.EMAIL_HOST_USER + '>', [user.email])

            return render(request, 'account.forgot.success.html')
    else:
        # Display new form for user to fill in
        form = forms.PasswordForgetForm()

    return render(request, 'account.forget.form.html', {'form': form})

def account_reset(request):
    if request.user.is_authenticated():
        pass
    else:
        if request.method == 'GET':
            # TODO: Error messages if key is not valid or email is wrong

            # Reset password for user who has forgotten it
            # Get user from request data
            user_email = request.GET.get('user')

            # Retrieve user from db
            try:
                user = User.objects.get(email=user_email)
            except User.DoesNotExist:
                return redirect('/accounts/forgot/?error=nouser')

            # Get reset key from request data
            reset_key_input = request.GET.get('key')

            # No reset key, throw to login page
            if reset_key_input is None:
                return redirect('/accounts/forgot/?error=nokey')

            # Match reset key
            algorithm, iterations, salt, hashed = user.password.split('$', 3)
            reset_key = make_password(user.email, salt, algorithm)
            algorithm, iterations, salt, reset_key = reset_key.split('$', 3)
            reset_key = reset_key[:-1]
            # Alternative char for + and /
            reset_key = reset_key.replace('+','-').replace('/','_')

            # Match keys
            if reset_key == reset_key_input:
                # Reset keys match, render page for user to reset
                # Store reset email in session
                request.session['reset_email'] = user_email

                form = forms.PasswordResetForm(initial={'email': user_email})
            else:
                # Key expired!
                return redirect('/accounts/forgot/?error=keymismatch')
        elif request.method == 'POST':
            form = forms.PasswordResetForm(request.POST)
            if form.is_valid():
                # Perform real resetting of account
                # Check if emails from form and session matches
                if form.cleaned_data['email'] == request.session['reset_email']:
                    # Get user
                    try:
                        user = User.objects.get(email=request.session['reset_email'])
                    except User.DoesNotExist:
                        return redirect('/accounts/forgot/?error=nouser')

                    # Update password of user in system
                    user.set_password(form.cleaned_data['password'])
                    user.save()

                    # Success, login user and display success page
                    user = authenticate(username=user.username, password=form.cleaned_data['password'])
                    login(request, user)

                    return render(request, 'account.reset.success.html')
                else:
                    return redirect('/accounts/forgot/?error=email')

        return render(request, 'account.reset.form.html', {'form': form})

@login_required
def survey(request):
    "Survey form for user to submit feedbacks"

    return render(request, 'itemrtweb/survey.form.html')

@login_required
def feedback(request):
    "Feedback form for user to submit feedbacks"

    if request.method == 'POST':
        form = forms.FeedbackForm(request.POST)
        if form.is_valid():
            # Maybe in the future this can be done in a webform with feedback id generated

            title = 'Feedback Received from ' + request.user.get_full_name()
            content = render_to_string('feedback.email', {'first_name': request.user.first_name, 'last_name': request.user.last_name, 'feedback': form.cleaned_data['feedback']})

            send_mail(title, content, settings.PROJECT_NAME + ' <' + settings.EMAIL_HOST_USER + '>', ['clangkts@gmail.com'])

            return render(request, 'itemrtweb/feedback.success.html')
    else:
        # Display new form for user to fill in
        form = forms.FeedbackForm()

    return render(request, 'itemrtweb/feedback.form.html', {'form': form})

def home(request):
    "Main page of the site, redirects if logged in"
    # Redirect to respective home portals
    if request.user.is_authenticated():

        # Record usage for stats purpose
        page = "home"
        # Never accessed this page before, or last access was more than 10 mins ago
        if 'user_usage_'+page not in request.session or datetime.now() > datetime.strptime(request.session['user_usage_'+page], "%a %b %d %H:%M:%S %Y") + timedelta(minutes=10):
            usage = UserUsage(user=request.user, page=page)
            usage.save()
            request.session['user_usage_'+page] = usage.datetime.strftime("%a %b %d %H:%M:%S %Y")
        # End usage recording

        if request.user.is_staff:
            # Redirect staff to staff portal
            return redirect('/control/')
        else:
            # Redirect user to user portal
            return redirect('/home/')

    # Home page for non authenticated users
    return render(request, 'itemrtweb/test.html')

@login_required
def user_home(request):
    "Home view to display practice or trial testing modes"

    return render(request, 'itemrtweb/home.html')

@login_required
def labtest(request):
    "Activate Lab Test with a test ID"
    if request.method == 'POST':
        return render(request, 'labtest.html', {'error': 'invalid'})
    else:
        return render(request, 'labtest.html')

@login_required
def papertest(request, test_id=None):
    "Boombastic function! Change with care."
    # Record usage for stats purpose
    page = "paper_test"
    # Never accessed this page before, or last access was more than 10 mins ago
    if 'user_usage_'+page not in request.session or datetime.now() > datetime.strptime(request.session['user_usage_'+page], "%a %b %d %H:%M:%S %Y") + timedelta(minutes=10):
        usage = UserUsage(user=request.user, page=page)
        usage.save()
        request.session['user_usage_'+page] = usage.datetime.strftime("%a %b %d %H:%M:%S %Y")
    # End usage recording

    # Obtain the list of topics
    topics = Topic.objects.all()

    if not test_id:
        if request.method == 'POST' and 'test_id' in request.POST and request.POST['test_id']:
            return redirect('/papertest/'+request.POST['test_id']+'/')
        elif request.method == 'POST' and 'num_qn' in request.POST and request.POST['num_qn'] and 'topics' in request.POST:
            # Check if all param is in
            # Get number of questions and difficulty

            numQns = int(request.POST['num_qn'])
            if numQns > 25:
                numQns = 25

            testid = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for i in range(6))

            #### VERY IMPORTANT TODO:: CHECK FOR UNIQUE ID
            new_test = Test(id=testid, assessment=Assessment.objects.all().get(name='Paper Test'))
            new_test.save()

            numQns = int(numQns)

            topics_selected = request.POST.getlist('topics')

            topics_all = list(topics.values_list('id', flat=True))

            for topic_id in topics_selected:
                topics_all.remove(int(topic_id))

            question_pool = Question.objects.all()
            question_pool = question_pool.exclude(topic__in=topics_all)

            for i in range (0, numQns):
                # Get a random question and add to paper
                question_pool = question_pool.exclude(id__in=new_test.questions.all().values_list('id'))

                if question_pool:
                    question = question_pool[random.randint(0, question_pool.count()-1)]
                    newTestQuestion = TestQuestion(question=question, test=new_test)
                    newTestQuestion.save()

            return redirect('/papertest/'+str(testid)+'/')
        elif request.method == 'POST':
            error = {}
            if 'num_qn' not in request.POST or not request.POST['num_qn']:
                error['num_qn'] = True
            return render(request, 'itemrtweb/papertest.home.html', {'error': error, 'topics': topics})

        return render(request, 'itemrtweb/papertest.home.html', {'topics': topics})
    else:
        # test_id is available, render test instead
        test = Test.objects.all().get(id=test_id)

        return render(request, 'itemrtweb/papertest.question.html', {'test': test})

@login_required
def papertestsubmit(request, test_id):
    test = Test.objects.all().get(id=test_id)

    if request.method == 'POST':
        # Check each question if it has been attempted
        for question in test.questions.all():
            try:
                # Previously saved response available? OK do nothing for now.
                test_response = TestResponse.objects.filter(test=test).filter(user=request.user).get(question=question)
                pass
            # Otherwise new response, create object
            except ObjectDoesNotExist:
                test_response = TestResponse(test=test, user=request.user, question=question, response='<No Answer Given>', criterion=question.marks, assessment=test.assessment)
                test_response.save()

        # Assign a score for each question
        total_ability = 0

        for question in test.questions.all():
            test_response = TestResponse.objects.filter(test=test).filter(user=request.user).get(question=question)

            response = test_response.response
            response = response.replace(' ', '').replace('\\n', '').replace('\\r', '').replace('\\t', '')

            # Get actual answer in string
            answer_text = question.choices[question.answers.all()[0].content.lower()]
            answer_text = answer_text.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')

            correctness = 0
            if re.match('^'+answer_text+'$', response):
                correctness = question.answers.all()[0].correctness

            print >> sys.stderr, response + " == " + answer_text + " : " + str(correctness)

            # Update correctness
            test_response.correctness = correctness

            # Update ability
            total_ability = total_ability + correctness
            test_response.ability = total_ability

            test_response.save()

        test.state = True
        test.save()

        # Prevent resubmission of test
        return redirect('/papertest/submit/' + test_id + '/')

    elif request.method == 'GET':
        return render(request, 'itemrtweb/papertest.submit.html', {'test': test, 'final_score': int(test.score)})

@login_required
def papertestutil(request, test_id=None, util_name=None):
    "Util functions for Boombastic function!"

    if test_id:
        test = Test.objects.all().get(id=test_id)
        # Util to return test endtime
        if util_name == 'getendtime':
            time = test.questions.count()*3
            endtime = test.generated+timedelta(minutes=time)

            return HttpResponse(endtime.isoformat())
        elif util_name == 'save':
            if 'qn_id' in request.POST and request.POST['qn_id']:
                # Get question (or nothing) from orm
                question = Question.objects.all().get(id=request.POST['qn_id'])

                # Check test not completed, question exists
                if test.state == False and test.questions.filter(id=question.id).exists():
                    # Check that there was a answer sent together with message
                    if 'answer' in request.POST and request.POST['answer']:
                        try:
                            # Previously saved response available? Resave if so!
                            test_response = TestResponse.objects.filter(test=test).filter(user=request.user).get(question=question)
                            test_response.response = request.POST['answer']
                            test_response.save()
                        # Otherwise new response, create object
                        except ObjectDoesNotExist:
                            test_response = TestResponse(test=test, user=request.user, question=question, response=request.POST['answer'], criterion=question.marks, assessment=test.assessment)
                            test_response.save()

                        return HttpResponse("Saved")
                    # Otherwise no answer just return nothing happened!
                    else:
                        return HttpResponse("Empty")
    raise Http404

@login_required
def trialtest(request):
    "Placeholder for trial test"
    # Obtain the list of topics
    topics = Topic.objects.all()

    # Record usage for stats purpose
    page = "cat_test"
    # Never accessed this page before, or last access was more than 10 mins ago
    if 'user_usage_'+page not in request.session or datetime.now() > datetime.strptime(request.session['user_usage_'+page], "%a %b %d %H:%M:%S %Y") + timedelta(minutes=10):
        usage = UserUsage(user=request.user, page=page)
        usage.save()
        request.session['user_usage_'+page] = usage.datetime.strftime("%a %b %d %H:%M:%S %Y")
    # End usage recording

    if 'complete' in request.GET and request.GET['complete']:
        complete = True
        if 'ability' in request.GET and request.GET['ability']:
            ability = request.GET['ability']
    else:
        complete = False
        ability = None

    return render(request, 'trialtest.html', {'topics':topics, 'complete': complete, 'ability': ability})

@login_required
def trialtest_generate(request):
    if request.method == 'POST':
        testid = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for i in range(6))

        #### VERY IMPORTANT TODO:: CHECK FOR UNIQUE ID
        new_test = Test(id=testid, assessment=Assessment.objects.all().get(name='CAT Test'))
        new_test.save()

        # Clear previous test questions if any
        request.session['trialtest_current_qn'] = None

        # Store topic in session, change this to db storage soon
        request.session['trialtest_topic_id'] = int(request.POST['topic'])

        return redirect('/trialtest/go/'+testid+'/')
    return redirect('/')

@login_required
def trialtest_go(request, test_id):
    # Obtain the list of topics
    topics = Topic.objects.all()

    # Get Test object
    test = Test.objects.all().get(id=test_id)

    # Selected topic
    topic_id = request.session['trialtest_topic_id']
    if topic_id > 0:
        topic = Topic.objects.all().get(id=topic_id)
    else:
        topic = None

    # Init session variable for question
    if 'trialtest_current_qn' not in request.session:
        request.session['trialtest_current_qn'] = None

    # Debug data
    debug = {}

    # Error data
    error = {}

    # GET Request or POST w/o session data >> Load Question
    # POST Request >> Answer Question
    if request.method == 'GET' or request.session['trialtest_current_qn'] is None:
        # Generate new question if not resuming
        if request.session['trialtest_current_qn'] == None:
            # Get assessment engine for CAT Test and dynamically load engine
            active_engine = Assessment.objects.all().get(name='CAT Test')
            engine = getattr(assessment_engine, active_engine.engine)()

            # Initialise session storage for assessment engine
            if 'engine_store' not in request.session:
                request.session['engine_store'] = None

            # Request a new question from the assessment engine
            question = engine.get_next_question(user=request.user, test=test, topic=topic, session_store=request.session['engine_store'])

            # Get current ability for debug purposes
            debug['ability'] = engine.get_user_ability(user=request.user, test=test)

            # Test ends if question is None (out of questions), redirect to completion screen
            if not question:
                return render(request, 'trialtest.html', {'topics':topics, 'complete': True, 'ability': engine.get_user_ability(user=request.user, test=test)})

            debug['answer'] = question.answers.all()[0].content

            # Update the question to session (for persistance if user refresh page/relogin)
            request.session['trialtest_current_qn'] = question.id

            # Update time starts from here
            request.session['trialtest_time'] = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        else:
            # Reload question from session data if resuming practice or page refresh
            question = Question.objects.all().get(id=request.session['trialtest_current_qn'])

        # Rendering at end of page
    else:
        # Submitting a test question
        if 'qid' in request.POST and request.POST['qid']:
            qnid_post = request.POST['qid']
        else:
            qnid_post = None

        qnid_session = request.session['trialtest_current_qn']

        if qnid_post != qnid_session:
            # Something strange is happening, missing qid from form or mismatch between form and session, TODO: Handle this PROPERLY
            debug['qnid_post'] = qnid_post
            debug['qnid_session'] = qnid_session

        # Reload question from session data
        question = Question.objects.all().get(id=qnid_session)

        # Check if answer was submitted
        if 'ans' in request.POST and request.POST['ans']:
            choice = request.POST['ans']

            # Get assessment engine for CAT Test and dynamically load engine
            active_engine = Assessment.objects.all().get(name='CAT Test')
            engine = getattr(assessment_engine, active_engine.engine)()

            # Initialise session storage for assessment engine
            if 'engine_store' not in request.session:
                request.session['engine_store'] = None

            # Match answer using assessment engine
            result = engine.match_answers(user=request.user, test=test, response=choice, question=question, session_store=request.session['engine_store'])

            # Restore updated engine store
            request.session['engine_store'] = result['session_store']

            # Reset current practice qn to None
            request.session['trialtest_current_qn'] = None

            # Answer is correct if full points is awarded
            if result['correctness'] == 1.0:
                correct = True
            else:
                correct = False

            # Get correct answer
            question.answer = question.answers.all()[0]

            # Terminating condition is true!
            if result['terminate']:
                ability_list = engine.get_user_ability_list(user=request.user, test=test)

                return render(request, 'trialtest.html', {'topics':topics, 'complete': True, 'ability': result['ability'], 'ability_list': ability_list, 'debug': result['debug_t_cond']})
            # Otherwise, no need to render a answer page, so we just save answers and then load next qn
#            else:
 #               return redirect(request.path)


            # Format question for web mode
            formatter = formatter_engine.WebQuestionFormatter()
            question = formatter.format(question)

            # Temp variable to allow ajax through https
            host = request.get_host()
            is_secure = not "localhost" in host

            # Kill debug for non test users
            if request.user.get_profile().debug is False:
                debug = {}

            return render(request, 'itemrtweb/trialtest.submit.html', {'question': question, 'topic': topic, 'choice': choice, 'correct': correct, 'debug': debug, 'host': host, 'is_secure': is_secure})
        else:
            # Option not selected, prompt error
            error['unselected'] = True

    # Format question for web mode
    formatter = formatter_engine.WebQuestionFormatter()
    question = formatter.format(question)

    # Kill debug for non test users
    if request.user.get_profile().debug is False:
        debug = {}

    # Render question page
    return render(request, 'itemrtweb/trialtest.question.html', {'question': question, 'topic': topic, 'error': error, 'debug': debug, 'test_id': test.id})

@login_required
def trialtestutil(request, test_id=None, util_name=None):
    "Util functions for Boombastic function!"

    if test_id:
        test = Test.objects.all().get(id=test_id)
        # Util to return question endtime
        if util_name == 'getendtime':
            # 5 mins from time the question was loaded
            endtime = datetime.strptime(request.session['trialtest_time'], "%a %b %d %H:%M:%S %Y") + timedelta(minutes=5)

            return HttpResponse(endtime.isoformat())
    raise Http404

@login_required
def practice_home(request):
    "Home view to display topics to choose from for practice"
    # Record usage for stats purpose
    page = "practice"
    # Never accessed this page before, or last access was more than 10 mins ago
    if 'user_usage_'+page not in request.session or datetime.now() > datetime.strptime(request.session['user_usage_'+page], "%a %b %d %H:%M:%S %Y") + timedelta(minutes=10):
        usage = UserUsage(user=request.user, page=page)
        usage.save()
        request.session['user_usage_'+page] = usage.datetime.strftime("%a %b %d %H:%M:%S %Y")
    # End usage recording

    # Obtain the list of topics
    topics = Topic.objects.all()
    print >> sys.stderr, topics

    active_engine = Assessment.objects.all().filter(active=True).get(type=Assessment.PRACTICE)
    engine = getattr(assessment_engine, active_engine.engine)()

    topic_ability = {}
    for topic in topics:
        ability = engine.get_user_ability(user=request.user, topic=topic)
        if ability is not None:
            topic_ability[topic] = int(ability)
        else:
            topic_ability[topic] = None

    # Check previous session
    previous_session = 'practice_current_qn' in request.session and request.session['practice_current_qn'] != None

    # Get list of questions that user has previously commented on
    questions_commented_id = Comment.objects.all().filter(content_type=ContentType.objects.get_for_model(Question)).filter(user=request.user).values_list('object_pk')
    questions_commented = Question.objects.all().filter(pk__in=questions_commented_id)

    # Debug data
    debug = {}
    debug['assessment_engine'] = active_engine
    debug['asd'] = 1

    # Kill debug for non test users
    if request.user.get_profile().debug is False:
        debug = {}

    return render(request, 'itemrtweb/practice.home.html', {'topics': topics, 'topic_ability': topic_ability, 'previous_session': previous_session, 'questions_commented': questions_commented, 'debug': debug})

@login_required
def practice_question(request, topic):
    # Selected topic
    topic = Topic.objects.all().get(id=topic)

    # Init session variable for question
    if 'practice_current_qn' not in request.session:
        request.session['practice_current_qn'] = None

    # Debug data
    debug = {}

    # Error data
    error = {}

    # GET Request or POST w/o session data >> Load Question
    # POST Request >> Answer Question
    if request.method == 'GET' or request.session['practice_current_qn'] is None:
        # Check if existing loaded question is from same topic, otherwise clear it
        if request.session['practice_current_qn'] != None:
            question_topic = Question.objects.all().get(id=request.session['practice_current_qn']).topic
            if question_topic != topic:
                # New practice topic, clear session variable
                request.session['practice_current_qn'] = None

        # Generate new question if not resuming
        if request.session['practice_current_qn'] == None:
            # Retrieve pool of questions with this topic
            question_pool = Question.objects.all().filter(topic=topic)

            # Get active assessment engine (practice) and dynamically load engine
            active_engine = Assessment.objects.all().filter(active=True).get(type=Assessment.PRACTICE)
            engine = getattr(assessment_engine, active_engine.engine)()

            # Initialise session storage for assessment engine
            if 'engine_store' not in request.session:
                request.session['engine_store'] = None

            # Request a new question from the assessment engine
            question = engine.get_next_question(user=request.user, topic=topic, question_pool=question_pool, session_store=request.session['engine_store'])

            # Get current ability for debug purposes
            debug['ability'] = engine.get_user_ability(user=request.user, topic=topic)

            debug['answer'] = question.choices[question.answers.all()[0].content.lower()]

            # Woops, we ran out of suitable questions, give error and direct to reset
            # TODO: Proper RESET (Currently when it runs out of questions it will just go back to home!)
            if not question:
                return redirect('/practice/')

            # Update the question to session (for persistance if user refresh page/relogin)
            request.session['practice_current_qn'] = question.id
        else:
            # Reload question from session data if resuming practice or page refresh
            question = Question.objects.all().get(id=request.session['practice_current_qn'])

        # Rendering at end of page
    else:
        # Submitting a practice question
        if 'qid' in request.POST and request.POST['qid']:
            qnid_post = request.POST['qid']
        else:
            qnid_post = None

        qnid_session = request.session['practice_current_qn']

        if qnid_post != qnid_session:
            # Something strange is happening, missing qid from form or mismatch between form and session, TODO: Handle this PROPERLY
            debug['qnid_post'] = qnid_post
            debug['qnid_session'] = qnid_session

        # Reload question from session data
        question = Question.objects.all().get(id=qnid_session)

        # Check if answer was submitted
        if 'ans' in request.POST and request.POST['ans']:
            choice = request.POST['ans']

            # Get active assessment engine (practice) and dynamically load engine
            active_engine = Assessment.objects.all().filter(active=True).get(type=Assessment.PRACTICE)
            engine = getattr(assessment_engine, active_engine.engine)()

            # Initialise session storage for assessment engine
            if 'engine_store' not in request.session:
                request.session['engine_store'] = None

            # Match answer using assessment engine
            result = engine.match_answers(user=request.user, response=choice, question=question, session_store=request.session['engine_store'])

            # Restore updated engine store
            # request.session['engine_store'] = result['session_store']

            # Answer is correct if full points is awarded
            if result['correctness'] == 1.0:
                correct = True
            else:
                correct = False

            # Get correct answer
            question.answer = question.answers.all()[0]

            # Ability score for debug purposes
            debug['ability'] = result['ability']

            # Reset current practice qn to None
            request.session['practice_current_qn'] = None

            # Format question for web mode
            formatter = formatter_engine.WebQuestionFormatter()
            question = formatter.format(question)

            # Temp variable to allow ajax through https
            host = request.get_host()
            is_secure = not "localhost" in host

            # Kill debug for non test users
            if request.user.get_profile().debug is False:
                debug = {}

            return render(request, 'itemrtweb/practice.submit.html', {'question': question, 'topic': topic, 'choice': choice, 'correct': correct, 'debug': debug, 'host': host, 'is_secure': is_secure})
        else:
            # Option not selected, prompt error
            error['unselected'] = True

    # Format question for web mode
    formatter = formatter_engine.WebQuestionFormatter()
    question = formatter.format(question)

    # Kill debug for non test users
    if request.user.get_profile().debug is False:
        debug = {}

    # Render question page
    return render(request, 'itemrtweb/practice.question.html', {'question': question, 'topic': topic, 'error': error, 'debug': debug})

@login_required
def practice_resume(request):
    "Restore practice session into last state"

    if 'practice_current_qn' in request.session and request.session['practice_current_qn'] != None:
        # Load previous question by going to the respective practice url
        # Retrieve topic from question id in session
        question = Question.objects.all().get(id=request.session['practice_current_qn'])
        topid_id = int(question.topic.id)

        # Redirect to correct topical practice page
        return redirect('/practice/'+str(topid_id)+'/')

    else:
        # Go back to main practice page
        return redirect('/practice/')

@login_required
def practice_end(request):
    "End current practice session"

    if 'practice_current_qn' in request.session:
        del request.session['practice_current_qn']

    # Go back to main practice page
    return redirect('/practice/')

@login_required
def question_view(request, id, practiced=False):
    "Lets the user view the question with answers"

    # Question exists?
    question = Question.objects.all().get(id=id)
    if question:
        # Check if user has done question if practiced = true
        if practiced:
            user_practiced = Response.objects.all().filter(user=request.user).filter(question=id)
            if not user_practiced:
                return redirect('/')

        # Load question and render
        # Get correct answer
        question.answer = question.answers.all()[0]

        # Format question for web mode
        formatter = formatter_engine.WebQuestionFormatter()
        question = formatter.format(question)

        # Temp variable to allow ajax through https
        host = request.get_host()
        is_secure = not "localhost" in host

        return render(request, 'itemrtweb/question.view.html', {'question': question, 'topic': question.topic, 'host': host, 'is_secure': is_secure})

    else:
        return redirect('/')

    pass

# additional view to list all possible questions

@user_passes_test(lambda u: u.is_superuser)
def admin(request):
    return render(request, 'itemrtweb/submit.html')

@user_passes_test(lambda u: u.is_superuser)
def system_health_check(request):
    # Check system to ensure only 1 (and not less) assessment per type (practice and test) is active

    # Check system to ensure all assessment engines can be loaded

    pass

@login_required
def debug_changemode(request, mode):
    mode = int(mode)

    if mode == 1:
        # Swap to Random Practice mode
        catengine = Assessment.objects.all().get(name='CAT Practice')
        randomengine = Assessment.objects.all().get(name='Random Practice')

        catengine.active = False
        randomengine.active = True

        catengine.save()
        randomengine.save()
    elif mode == 2:
        # Swap to CAT Practice mode
        catengine = Assessment.objects.all().get(name='CAT Practice')
        randomengine = Assessment.objects.all().get(name='Random Practice')

        catengine.active = True
        randomengine.active = False

        catengine.save()
        randomengine.save()

    return HttpResponseRedirect('/home/')

@login_required
def debug_clearresponses(request):
    # Clears all responses for current user

    request.session['engine_store'] = None

    Response.objects.all().filter(user=request.user).delete()

    return redirect('/practice/')

@user_passes_test(lambda u: u.is_staff)
def control(request):
    "Control Panel Code"
    # Obtain the list of topics
    tests = Test.objects.all()

    testcount = tests.count()

    return render_to_response('itemrtweb/control-empty.html', {'tests': tests, 'testcount': testcount}, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff)
def control_cattest_settings(request):
    topics = Topic.objects.all()

    return render(request, 'itemrtweb/control-createnewtest.html', {'topics': topics})

@user_passes_test(lambda u: u.is_staff)
def controlnewtest(request):
    "Control Panel Code"
    # Obtain the list of topics
    tests = Test.objects.all()

    return render_to_response('itemrtweb/control-createnewtest.html', {'tests': tests}, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff)
def controlnewtest_submit(request):
    "Control Panel Code"
    # Obtain the list of topics
    if request.method == 'POST' and request.POST['newtestNumOfQns']:
        numQns = request.POST['newtestNumOfQns']

        testid = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for i in range(6))

        #### VERY IMPORTANT TODO:: CHECK FOR UNIQUE ID
        new_test = Test(id=testid, assessment=Assessment.objects.all().get(name='Generic Test'))
        new_test.save()

        numQns = int(numQns)

        for i in range (0, numQns):
            # Get a random question and add to paper
            question_pool = Question.objects.all().filter(topic=1)
            question_pool = question_pool.exclude(id__in=new_test.questions.all().values_list('id'))

            if question_pool:
                question = question_pool[random.randint(0, question_pool.count()-1)]
                newTestQuestion = TestQuestion(question=question, test=new_test)
                newTestQuestion.save()


    return render_to_response('itemrtweb/control-createnewtest.html', {'testid': testid}, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff)
def controlviewpaper(request, testid):
    "Control Panel Code"
    # Obtain the list of topics
    tests = Test.objects.all()

    # Get this test
    thisTest = Test.objects.all().get(id=testid)

    # Home mode
        # Show test responses
        # Open paper for testing
        # Download paper in LaTeX format

    # Question modecontrol_cattest_settingsconcontrol_cattest_settingstrol_cattest_settings
        # Display all questions in test
        # Display dummy modify button
    questions = thisTest.questions.all()

    averagediff = thisTest.questions.all().aggregate(Avg('difficulty')).values()[0]

    # Stats mode
        # Currently not used
        # Paper users, scores, etc

    return render_to_response('itemrtweb/control.html', {'tests': tests, 'testid': testid, 'thistest': thisTest, 'questions': questions, 'avgdiff': averagediff}, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff)
def controldownloadpaper(request, testid):
    "Control Panel Code"
    # Obtain the list of topics
    tests = Test.objects.all()

    # Get this test
    thisTest = Test.objects.all().get(id=testid)

    # Home mode
        # Show test responses
        # Open paper for testing
        # Download paper in LaTeX format

    # Question mode
        # Display all questions in test
        # Display dummy modify button
    questions = thisTest.questions.all()

    averagediff = thisTest.questions.all().aggregate(Avg('difficulty')).values()[0]

    # Stats mode
        # Currently not used
        # Paper users, scores, etc

    return render_to_response('itemrtweb/download.tex', {'tests': tests, 'testid': testid, 'thistest': thisTest, 'questions': questions, 'avgdiff': averagediff}, context_instance=RequestContext(request))

@csrf_exempt
def postdata(request):
    if request.method == 'POST':

        # loop through keys and values
        for key, value in request.POST.iteritems():
            pass

        return render_to_response('postdata.html', {'postdata': request.POST}, context_instance=RequestContext(request))

@user_passes_test(lambda u: u.is_staff)
def prototype(request, question_id=None):
    # Init
    selected_question = None

    # Obtain the list of topics
    topics = Topic.objects.all()

    # Objectify the selected question
    if question_id:
        selected_question = Question.objects.all().get(id=int(question_id))

    if request.method == 'POST':
        form = forms.InsertEditQuestionForm(request.POST) # Bind to user submitted form
        if form.is_valid():
            # Check if question exists or need to create new
            if selected_question:
                # Edit existing question
                selected_question.content=form.cleaned_data['content']
                selected_question.difficulty=form.cleaned_data['difficulty']
                selected_question.topic=form.cleaned_data['topic']
                selected_question.save()

                answer = selected_question.answers.all()[0]
                answer.content = form.cleaned_data['answer']
                answer.save()

                # Insert solution if exists
                if form.cleaned_data['solution']:
                    # Check if solution exists
                    solution_exists = Solution.objects.all().filter(question=selected_question).count()

                    if solution_exists > 0:
                        # Update solution
                        solution = selected_question.solution
                        solution.content = form.cleaned_data['solution']
                        solution.save()
                    else:
                        # New solution for this question
                        solution = Solution(question=selected_question, content=form.cleaned_data['solution'])
                        solution.save()

                # Tag adding/deleting
                selected_question.tags.clear()
                for tag_name in form.cleaned_data['tags']:
                    # Check tag exists in db, otherwise add
                    # Currently no need since automatically verified
                    tag = Tag.objects.all().get(name=tag_name)

                    qn_tag = QuestionTag(question=selected_question, tag=tag)
                    qn_tag.save()

                return redirect('/prototype2/list/topic/'+ str(selected_question.topic.id) +'/?msg=Question '+ str(selected_question.id) +' edited successfully#question-'+ str(selected_question.id))
            else:
                # Insert new question
                question = Question(content=form.cleaned_data['content'], difficulty=form.cleaned_data['difficulty'], topic=form.cleaned_data['topic'])
                question.save()

                # Insert answer for question
                answer = Answer(question=question, content=form.cleaned_data['answer'])
                answer.save()

                # Insert solution if exists
                if form.cleaned_data['solution']:
                    solution = Solution(question=question, content=form.cleaned_data['solution'])
                    solution.save()

                for tag_name in form.cleaned_data['tags']:
                    # Check tag exists in db, otherwise add
                    # Currently no need since automatically verified
                    tag = Tag.objects.all().get(name=tag_name)

                    qn_tag = QuestionTag(question=question, tag=tag)
                    qn_tag.save()

                # Question inserted successfully!
                return redirect('/prototype2/list/topic/'+ str(question.topic.id) +'/?msg=Question '+ str(question.id) +' added successfully#question-'+ str(question.id))

        # Reply regardless valid
        return render(request, 'itemrtweb/manage.question.form.html', {'form': form, 'topics': topics, 'selected_question': selected_question})
    else:
        # Check if question exists or give blank form
        if selected_question:
            # Load existing question into a form
            form = forms.InsertEditQuestionForm(initial={'content':selected_question.content, 'difficulty':selected_question.difficulty, 'topic':selected_question.topic, 'answer':selected_question.answers.all()[0].content, 'tags': selected_question.tags.all().values_list('name', flat=True)})

            solution_exists = Solution.objects.all().filter(question=selected_question).count()

            if solution_exists > 0:
                form.fields["solution"].initial = selected_question.solution.content
        else:
            # Display new form for user to fill in
            form = forms.InsertEditQuestionForm()

    return render(request, 'itemrtweb/manage.question.form.html', {'form': form, 'topics': topics, 'selected_question': selected_question})

@user_passes_test(lambda u: u.is_staff)
def prototype3(request, question_id=None):
    # Init
    selected_question = None

    # Obtain the list of topics
    topics = Topic.objects.all()

    # Objectify the selected question
    if question_id:
        selected_question = Question.objects.all().get(id=int(question_id))

    # Check if question exists otherwise redirect to question list
    if selected_question:
        # Hide question and save. Then give message to user
        selected_question.is_active = False
        selected_question.save()

        return redirect('/prototype2/?msg=Question has been deleted')
    else:
        # Redirect user back to question lists
        return redirect('/prototype/')

@user_passes_test(lambda u: u.is_staff)
def prototype2(request, topic_id=None):
    # Record usage for stats purpose
    page = "question_management"
    # Never accessed this page before, or last access was more than 10 mins ago
    if 'user_usage_'+page not in request.session or datetime.now() > datetime.strptime(request.session['user_usage_'+page], "%a %b %d %H:%M:%S %Y") + timedelta(minutes=10):
        usage = UserUsage(user=request.user, page=page)
        usage.save()
        request.session['user_usage_'+page] = usage.datetime.strftime("%a %b %d %H:%M:%S %Y")
    # End usage recording

    # Init
    filtered_questions = None
    selected_topic = None

    # Obtain the list of topics
    topics = Topic.objects.all()
    all_tags = Tag.objects.all()

    # int the selected topic
    if topic_id:
        selected_topic = Topic.objects.all().get(id=int(topic_id))

    if topic_id:
        # Retrieve questions for this topic
        filtered_questions = Question.objects.all().filter(topic=topic_id)

        # Filter for difficulty if specified
        if request.GET.__contains__('difficulty'):
            difficulty = request.GET.get('difficulty')

            # Only filter if input is an int!
            try:
                difficulty = int(difficulty)
                filtered_questions = filtered_questions.filter(difficulty=difficulty)
            except exceptions.ValueError:
                pass

    return render(request, 'itemrtweb/manage.question.list.html', {'topics': topics, 'selected_topic': selected_topic, 'questions': filtered_questions, 'all_tags': all_tags})

@user_passes_test(lambda u: u.is_staff)
def prototype2a(request):
    # Init
    filtered_questions = Question.objects.all()

    # Obtain the list of topics
    topics = Topic.objects.all()
    all_tags = Tag.objects.all()

    # Filter by tags given from input
    tags = request.GET.getlist("tags")

    print >> sys.stderr, tags

    if tags:
        for tag in tags:
            print >> sys.stderr, tag
            filtered_questions = filtered_questions.filter(tags__name=tag)
    else:
        filtered_questions = None

    return render(request, 'itemrtweb/manage.question.list.html', {'topics': topics, 'questions': filtered_questions, 'tags': tags, 'all_tags': all_tags})

@user_passes_test(lambda u: u.is_staff)
def preview(request, question_id=None):
    # Init
    selected_question = None

    # Objectify the selected question
    if question_id:
        selected_question = Question.objects.all().get(id=int(question_id))
        # Get correct answer
        selected_question.answer = selected_question.answers.all()[0]

    # Check if question exists otherwise redirect to question list
    if selected_question:
        return render(request, 'itemrtweb/manage.question.preview.html', {'question': selected_question})
    else:
        # 404 if question was not found
        raise Http404

@user_passes_test(lambda u: u.is_staff)
def testquestion(request, question_id=None):


    if question_id is not None:
        # Get question (or nothing) from orm
        question = Question.objects.all().get(id=question_id)

        if 'answer' in request.POST and request.POST['answer']:
            response = request.POST['answer']
            response = response.replace(' ', '').replace('\\n', '').replace('\\r', '').replace('\\t', '')

            # Get actual answer in string
            answer_text = question.choices[question.answers.all()[0].content.lower()]
            answer_text = answer_text.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')

            print sys.stderr, answer_text

            if re.match('^'+answer_text+'$', response):
                return HttpResponse("Answer is Correct")
            else:
                return HttpResponse("Answer do not Match\nInput: "+ response+ "\nActual: "+ answer_text)
        # Otherwise no answer just return nothing happened!
        else:
            return HttpResponse("Empty Field!")
    raise Http404

@login_required
def flag_question(request, question_id):
    "View to allow users to flag/report a problem with the question"

    if request.method == 'POST':
        form = forms.FlagQuestionForm(request.POST)
        if form.is_valid():
            # Get the question from orm
            question = Question.objects.get(id=question_id)

            # Flag question now!
            flag = QuestionFlag(question=question, user=request.user, issue=form.cleaned_data['issue'])
            flag.save()

            return render(request, 'itemrtweb/question.flag.html', {'form': form, 'submitted': True})
    else:
        # Display new form for user to fill in
        form = forms.FlagQuestionForm()

    return render(request, 'itemrtweb/question.flag.html', {'form': form})

@user_passes_test(lambda u: u.is_staff)
def flag_display(request):
    flagged_qns = QuestionFlag.objects.all()

    return render(request, 'itemrtweb/control.flaggedquestions.html', {'flagged_qns': flagged_qns})

@login_required
def search(request):
    # Init
    filtered_questions = Question.objects.all()

    # Obtain the list of topics
    topics = Topic.objects.all()
    all_tags = Tag.objects.all()

    # Filter by tags given from input
    tags = request.GET.getlist("tags")

    if tags:
        for tag in tags:
            filtered_questions = filtered_questions.filter(tags__name=tag)

            paginator = Paginator(filtered_questions, 5)

            page = request.GET.get('page')

            try:
                questions = paginator.page(page)
            except PageNotAnInteger:
                questions = paginator.page(1)
            except EmptyPage:
                questions = paginator.page(paginator.num_pages)
    else:
        questions = None

    # Remove page number from querystring
    q = request.GET
    z = q.copy()
    try:
        del z['page']
    except KeyError:
        pass
    querystring = '?' + z.urlencode()

    return render(request, 'itemrtweb/search.html', {'topics': topics, 'questions': questions, 'tags': tags, 'all_tags': all_tags, 'querystring': querystring})