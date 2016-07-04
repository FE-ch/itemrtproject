from django import template
from django.utils.html import escape

import re

register = template.Library()

@register.filter(name='formatquestionforweb')
def format_question_for_web(value):
    value = re.sub(r'\\begin{code}\r\n', '<pre class="prettyprint linenums">', value)
    value = re.sub(r'\\end{code}\r\n', '</pre>', value)

    index_start_pre = value.find('<pre class="prettyprint linenums">')
    index_end_pre = value.find('</pre>')

    front_string = escape(value[:index_start_pre])
    safe_string = escape(value[index_start_pre+34:index_end_pre])
    back_string = escape(value[index_end_pre+6:])

    value = front_string + '<pre class="prettyprint linenums">' + safe_string + '</pre>' + back_string

    return value

@register.filter(name='keyvalue')
def key_value(dict, key):
    return dict[key]