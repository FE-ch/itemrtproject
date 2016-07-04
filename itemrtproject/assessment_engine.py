from itemrtdb.models import *
from django.db.models import Avg

import abc, random, re, decimal, math, sys

# Please note: When adding a new engine here, please be sure to follow the interface (base) specifications. This will allow your code to work peacefully with the rest of the system. RandomPracticeEngine is a good sample of what to expect.
# Your can store your states persistantly for current session using session_store variable. This is persistant throughout the user session but it should be rebuilt from sql data if necessary.
# Lastly, each engine is tagged to the database Assessment table. After adding a new engine, please be sure to add a new row in that table so that you can try out your newly implemented assessment engine.

class PracticeEngineBase(object):

    """Base abstract class for implementing practice assessment engine and algorithms."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_next_question(self, user, topic, question_pool, session_store):        # Redudant to have question pool that is filtered?
        """Return a question by selecting from a pool of questions."""
        return

    @abc.abstractmethod
    def get_user_ability(self, user, topic):
        """Returns the user's overall ability between 0 and 100."""
        return

    @abc.abstractmethod
    def match_answers(self, user, response, question, session_store):
        """Match and record user's response with answers and update ability scores."""
        return

class RandomPracticeEngine(PracticeEngineBase):

    """
    Assessment engine that picks questions at random for practices.
    User's ability is computed by average correctness of attempted questions.

    """

    def get_next_question(self, user, topic, question_pool, session_store):
        # Get tested questions and omit them from question pool
        question_tested = Response.objects.all().filter(user=user).filter(assessment__name__exact='Random Practice').filter(question__topic__exact=topic).values_list('question')
        question_pool = question_pool.exclude(id__in=question_tested)

        question = None

        # Get a random question
        if question_pool:
            question = question_pool[random.randint(0, question_pool.count()-1)]

        return question

    def get_user_ability(self, user, topic):
        # Get user's ability from last attempted question
        response = Response.objects.all().filter(user=user).filter(assessment__name__exact='Random Practice').filter(question__topic__exact=topic).order_by('-date')

        if response.count() < 3:
            return None
        else:
            return response[0].ability

    def match_answers(self, user, response, question, session_store):
        # Get correctness of answer (between 0 and 1)
        correctness = 0
        for answer in question.answers.all():
            if re.search(answer.content, response, re.IGNORECASE):
                correctness = answer.correctness

        # Update user's current ability
        user_score = question.marks * correctness
        total_score = question.marks

        responses = Response.objects.all().filter(user=user).filter(assessment__name__exact='Random Practice').filter(question__topic__exact=question.topic)
        for prev_response in responses:
            user_score += prev_response.correctness * prev_response.criterion
            total_score += prev_response.criterion

        new_ability = user_score/total_score * 100

        # Record response and ability
        this_engine = Assessment.objects.all().get(name='Random Practice')
        new_response = Response(user=user, question=question, response=response, assessment=this_engine, correctness=correctness, criterion=question.marks, ability=new_ability)
        new_response.save()

        reply_vector = {'session_store': session_store, 'correctness': correctness, 'ability': new_ability}

        return reply_vector

class CATPracticeEngine(PracticeEngineBase):

    """
    Assessment engine that uses an implementation of computerised adaptive testing to pick questions for practices.
    User's ability is determined by the current ability level of user.

    """

    def get_next_question(self, user, topic, question_pool, session_store):
        this_engine = Assessment.objects.all().get(name='CAT Practice')

        # Rebuild session store
        if not session_store or session_store['engine'] != this_engine or session_store['topic'] != topic:
            session_store = {}
            session_store['engine'] = this_engine
            session_store['topic'] = topic
            session_store['numerator'] = 0
            session_store['denominator'] = 0
            session_store['ability'] = 0

            # Rebuild ability score from data
            responses = Response.objects.all().filter(user=user).filter(assessment=this_engine).filter(question__topic__exact=topic)
            for prev_response in responses:
                session_store = self._compute_ability(session_store, prev_response.criterion, prev_response.correctness)

        # Get tested questions and omit them from question pool
        question_tested = Response.objects.all().filter(user=user).filter(assessment=this_engine).filter(question__topic__exact=topic).values_list('question')
        question_pool = question_pool.exclude(id__in=question_tested)

        selected_question = None

        # Get a question using ability score (Legacy CAT code)
        max_info = -4
        question_info = {}
        best_questions = []

        for question in question_pool:
            # Normalisation of question difficulty due to remapped range (from -3 to +3 >> 1 to 5)
            difficulty = ((question.difficulty-1.0)/4.0 * 6.0)-3.0

            temp = 0
            temp = self._compute_item_info(session_store, difficulty)
            temp = temp * (1-temp)
            question_info[question.id] = temp
            if temp > max_info:
                max_info = temp
                best_questions = []
                best_questions.append(question)
            elif temp == max_info:
                best_questions.append(question)

        if best_questions:
            selected_question = best_questions[random.randint(0, len(best_questions)-1)]
            selected_question.question_info = question_info

        return selected_question

    def get_user_ability(self, user, topic):
        # Get user's ability from last attempted question
        response = Response.objects.all().filter(user=user).filter(assessment__name__exact='CAT Practice').filter(question__topic__exact=topic).order_by('-date')

        if response.count() < 3:
            return None
        else:
            return response[0].ability

    def match_answers(self, user, response, question, session_store):
        this_engine = Assessment.objects.all().get(name='CAT Practice')

        # Get correctness of answer (between 0 and 1)
        correctness = 0
        for answer in question.answers.all():
            if re.search(answer.content, response, re.IGNORECASE):
                correctness = answer.correctness

        # Rebuild session store
        if not session_store or session_store['engine'] != this_engine or session_store['topic'] != question.topic:
            session_store = {}
            session_store['engine'] = this_engine
            session_store['topic'] = question.topic
            session_store['numerator'] = 0
            session_store['denominator'] = 0
            session_store['ability'] = 0

            # Rebuild ability score from data
            responses = Response.objects.all().filter(user=user).filter(assessment=this_engine).filter(question__topic__exact=question.topic)
            for prev_response in responses:
                session_store = self._compute_ability(session_store, prev_response.criterion, prev_response.correctness)

        # Normalisation of question difficulty due to remapped range (from -3 to +3 >> 1 to 5)
        difficulty = ((question.difficulty-1.0)/4.0 * 6.0)-3.0

        # Compute new ability score
        session_store = self._compute_ability(session_store, difficulty, correctness)
        normalised_ability = (session_store['ability'] + 3)/6 * 100

        # Record response and ability
        new_response = Response(user=user, question=question, response=response, assessment=this_engine, correctness=correctness, criterion=difficulty, ability=normalised_ability)
        new_response.save()

        reply_vector = {'session_store': session_store, 'correctness': correctness, 'ability': normalised_ability}

        return reply_vector

    def _compute_ability(self, session_store, difficulty, correctness):
        # Legacy CAT code ported from older fyp systems
        if correctness >= decimal.Decimal('0.75'):
            # Consider correct if >= 0.75
            session_store['numerator'] += 1 - self._compute_item_info(session_store, difficulty)
        else:
            session_store['numerator'] += 0 - self._compute_item_info(session_store, difficulty)

        temp = self._compute_item_info(session_store, difficulty)
        temp = temp * (1-temp)
        session_store['denominator'] += temp

        if session_store['denominator'] != 0:
            session_store['ability'] += session_store['numerator'] / session_store['denominator']

        if session_store['ability'] > 3:
            session_store['ability'] = 3
        if session_store['ability'] < -3:
            session_store['ability'] = -3

        return session_store


    def _compute_item_info(self, session_store, difficulty):
        # magical code.
        a = 1
        b = float(difficulty)
        c = 0
        theta = session_store['ability']

        p_theta = 0
        p_theta = c + (1-c) * 1/(1 + math.exp(-a * (theta - b)))

        p_theta = p_theta * a * a

        return p_theta

class TestEngineBase(object):

    """Base abstract class for implementing test assessment engine and algorithms."""

    __metaclass__ = abc.ABCMeta

    #@abc.abstractmethod
    #def get_next_question(self, user, topic, question_pool, session_store):        # Redudant to have question pool that is filtered?
    #    """Return a question by selecting from a pool of questions."""
    #    return

    #@abc.abstractmethod
    #def get_user_ability(self, user, topic):
    #    """Returns the user's overall ability between 0 and 100."""
    #    return

    @abc.abstractmethod
    def match_answers(self, user, test, response, response_type, question, session_store):
        """Match and record user's response with answers and update ability scores."""
        return

class CATTestEngine(TestEngineBase):

    """
    Test engine that uses an implementation of computerised adaptive testing to pick questions for tests.
    User's ability is determined by the current ability level of user.
    Once the ability falls within a range, test will stop.

    """

    def get_next_question(self, user, test, topic, session_store):
        # Small note: topic can be None. This happens when All Topics is chosen

        this_engine = Assessment.objects.all().get(name='CAT Test')

        # Rebuild session store
        if not session_store or session_store['engine'] != this_engine.name or session_store['test'] != test.id:
            session_store = {}
            session_store['engine'] = this_engine.name
            session_store['test'] = test.id
            session_store['numerator'] = 0
            session_store['denominator'] = 0
            session_store['ability'] = 0
            session_store['stderr'] = 0

            # Rebuild ability score from data
            responses = TestResponse.objects.all().filter(test=test)
            for prev_response in responses:
                session_store = self._compute_ability(session_store, prev_response.criterion, prev_response.correctness)

        # Get tested questions and omit them from question pool
        question_tested = TestResponse.objects.all().filter(test=test).values_list('question')
        question_pool = Question.objects.all().exclude(id__in=question_tested)
        # Don't filter by topic if it is not given
        if topic is not None:
            question_pool = question_pool.filter(topic=topic)
        else:
            # If topic is none, load the topics
            topic_pool = Topic.objects.all()

        selected_question = None

        # Get a question using ability score (Legacy CAT code)
        #max_info = -4
        min_info = 2
        question_info = {}
        best_questions = []

        for question in question_pool:
            # Normalisation of question difficulty due to remapped range (from -3 to +3 >> 1 to 5)
            difficulty = ((question.difficulty-1.0)/4.0 * 6.0)-3.0

            temp = 0
            temp = self._compute_item_info(session_store, difficulty)
            fitness = 1 - (temp * (1-temp))

#            if topic is None:
 #               topic_weight = 0
  #              topic_total = 0
   #             for atopic in topic_pool:
    #                topic_total = topic_total + atopic.weight
     #               if atopic == question.topic:
      #                  topic_weight = atopic.weight * 1
#
 #               topic_weight = topic_weight/topic_total
  #              fitness = fitness + 1 - topic_weight

            question_info[question.id] = fitness
            #if temp > max_info:
            #    max_info = temp
            # goal is to minimize
            if fitness < min_info:
                min_info = fitness
                best_questions = []
                best_questions.append(question)
            elif fitness == min_info:
                best_questions.append(question)

        if best_questions:
            if topic is None:
                question_info[0] = 100
            else:
                question_info[0] = 1

            selected_question = best_questions[random.randint(0, len(best_questions)-1)]
            selected_question.question_info = question_info

        return selected_question

    def get_user_ability(self, user, test):
        # Get user's ability from last attempted question
        response = TestResponse.objects.all().filter(test=test).order_by('-date')

        if response.count() == 0:
            return None
        else:
            return response[0].ability

    def get_user_ability_list(self, user, test):
        # Get user's ability from last attempted question
        ability_list = TestResponse.objects.all().filter(test=test).order_by('date').values_list('ability', flat=True)

        if len(ability_list) == 0:
            return None
        else:
            return ability_list

    def match_answers(self, user, test, response, question, session_store, response_type='mcq'):
        this_engine = Assessment.objects.all().get(name='CAT Test')

        # Get correctness of answer (between 0 and 1)
        correctness = 0
        for answer in question.answers.all():
            if re.search('^'+answer.content+'$', response, re.IGNORECASE):
                correctness = answer.correctness

        # Rebuild session store
        if not session_store or session_store['engine'] != this_engine.name or session_store['test'] != test.id:
            session_store = {}
            session_store['engine'] = this_engine.name
            session_store['test'] = test.id
            session_store['numerator'] = 0
            session_store['denominator'] = 0
            session_store['ability'] = 0
            session_store['stderr'] = 0

            # Rebuild ability score from data
            responses = TestResponse.objects.all().filter(test=test)
            for prev_response in responses:
                session_store = self._compute_ability(session_store, prev_response.criterion, prev_response.correctness)

        # Normalisation of question difficulty due to remapped range (from -3 to +3 >> 1 to 5)
        difficulty = ((question.difficulty-1.0)/4.0 * 6.0)-3.0

        # Compute new ability score
        session_store = self._compute_ability(session_store, difficulty, correctness)
        normalised_ability = (session_store['ability'] + 3)/6 * 100

        # Record response and ability
        new_response = TestResponse(test=test, user=user, question=question, response=response, assessment=this_engine, correctness=correctness, criterion=difficulty, ability=normalised_ability)
        new_response.save()

        # Check for terminating conditions
        # 1. Stderr less than 0.677
        # 2. 10 attempts max
        # 3. 4x repeat max (3) or min (-3) ability
        terminate = False
        debug_t_cond = 0

        if session_store['stderr'] < 0.677:
            terminate = True
            debug_t_cond = 1
        if TestResponse.objects.all().filter(test=test).count() >= 10:
            terminate = True
            debug_t_cond = 2
        if normalised_ability == 100 or normalised_ability == 0:
            if TestResponse.objects.all().filter(test=test).count() >= 4:
                last_four_ability = TestResponse.objects.all().filter(test=test).order_by('-date')[:4].values_list('ability', flat=True)
                last_avg_ability = sum(last_four_ability)/len(last_four_ability)
                if last_avg_ability == 100 or last_avg_ability == 0:
                    terminate = True
                    debug_t_cond = 3

        reply_vector = {'session_store': session_store, 'terminate': terminate, 'ability': normalised_ability, 'debug_t_cond': debug_t_cond, 'correctness': correctness}

        return reply_vector

    def _compute_ability(self, session_store, difficulty, correctness):
        # Legacy CAT code ported from older fyp systems
        if correctness >= decimal.Decimal('0.75'):
            # Consider correct if >= 0.75
            session_store['numerator'] += 1 - self._compute_item_info(session_store, difficulty)
        else:
            session_store['numerator'] += 0 - self._compute_item_info(session_store, difficulty)

        temp = self._compute_item_info(session_store, difficulty)
        temp = temp * (1-temp)
        session_store['denominator'] += temp

        if session_store['denominator'] != 0:
            session_store['ability'] += session_store['numerator'] / session_store['denominator']
            session_store['stderr'] = 1 / math.sqrt(session_store['denominator'])

        if session_store['ability'] > 3:
            session_store['ability'] = 3
        if session_store['ability'] < -3:
            session_store['ability'] = -3

        return session_store


    def _compute_item_info(self, session_store, difficulty):
        # magical code.
        a = 1
        b = float(difficulty)
        c = 0
        theta = session_store['ability']

        p_theta = 0
        p_theta = c + (1-c) * 1/(1 + math.exp(-a * (theta - b)))

        p_theta = p_theta * a * a

        return p_theta

class PaperTestEngine(TestEngineBase):

    """Test Engine for Paper Test"""

    def match_answers(self, user, test, response, response_type, question, session_store):
        """Match and record user's response with answers and update ability scores."""

        # Get correctness of answer (between 0 and 1)
        # TODO: Code currently does not cater to multi answers
        # TODO: Code currently does not cater to different types of qn (see models qn type)
        correctness = 0
        for answer in question.answers.all():
            if response_type == "fillblank":
                # Get actual answer in string
                answer_text = question.choices[answer.content.lower()]
                if re.match('^'+answer_text+'$', response):
                    correctness = answer.correctness
            else : #mcq
                if re.match(answer.content, response, re.IGNORECASE):
                    correctness = answer.correctness

        # Update user's current ability
        user_score = question.marks * correctness
        total_score = question.marks

        responses = TestResponse.objects.all().filter(user=user).filter(assessment__name__exact='Paper Test').filter(test=test)
        for prev_response in responses:
            user_score += prev_response.correctness * prev_response.criterion
            total_score += prev_response.criterion

        new_ability = user_score/total_score * 100

        # Record response and ability
        this_engine = Assessment.objects.all().get(name='Paper Test')
        new_response = TestResponse(test=test, user=user, question=question, response=response, assessment=this_engine, correctness=correctness, criterion=question.marks, ability=new_ability)
        new_response.save()

        reply_vector = {'session_store': session_store, 'correctness': correctness, 'ability': new_ability}

        return reply_vector