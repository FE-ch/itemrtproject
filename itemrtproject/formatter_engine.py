import abc, random, re
from django.utils.html import escape

class QuestionFormatterBase(object):

    """Base abstract class for implementing practice formatter engine for output of questions."""

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def format(self, question, **args):
        """Return a question by selecting from a pool of questions."""
        return

class WebQuestionFormatter(QuestionFormatterBase):

    """
    for web
    """

    def format(self, question, **args):
        """
        Escape everything except the pre tags, assume only 1 pre
        """

        if question.content.find('begin{code}') > 0:
            question.content = re.sub(r'\\begin{code}\r\n', '<pre class="prettyprint linenums">', question.content)
            question.content = re.sub(r'\\end{code}\r\n', '</pre>', question.content)

            index_start_pre = question.content.find('<pre class="prettyprint linenums">')
            index_end_pre = question.content.find('</pre>')

            front_string = escape(question.content[:index_start_pre])
            safe_string = escape(question.content[index_start_pre+34:index_end_pre])
            back_string = escape(question.content[index_end_pre+6:])

            question.content = front_string + '<pre class="prettyprint linenums">' + safe_string + '</pre>' + back_string

        return question

class LatexQuestionFormatter(QuestionFormatterBase):

    """
    for output in latex format
    """

    def format(self, question, **args):

        return question