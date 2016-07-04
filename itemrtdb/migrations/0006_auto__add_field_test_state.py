# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding field 'Test.state'
        db.add_column(u'itemrtdb_test', 'state',
                      self.gf('django.db.models.fields.BooleanField')(default=False),
                      keep_default=False)


    def backwards(self, orm):
        # Deleting field 'Test.state'
        db.delete_column(u'itemrtdb_test', 'state')


    models = {
        u'auth.group': {
            'Meta': {'object_name': 'Group'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'auth.permission': {
            'Meta': {'ordering': "(u'content_type__app_label', u'content_type__model', u'codename')", 'unique_together': "((u'content_type', u'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        u'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        u'itemrtdb.answer': {
            'Meta': {'object_name': 'Answer'},
            'content': ('django.db.models.fields.TextField', [], {'max_length': '100'}),
            'correctness': ('django.db.models.fields.DecimalField', [], {'default': '1', 'max_digits': '3', 'decimal_places': '2'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'question': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'answers'", 'to': u"orm['itemrtdb.Question']"})
        },
        u'itemrtdb.assessment': {
            'Meta': {'object_name': 'Assessment'},
            'active': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'engine': ('django.db.models.fields.CharField', [], {'max_length': '30'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '30'}),
            'type': ('django.db.models.fields.CharField', [], {'max_length': '1'})
        },
        u'itemrtdb.meta': {
            'Meta': {'object_name': 'Meta'},
            'metatag': ('django.db.models.fields.CharField', [], {'max_length': '30', 'primary_key': 'True'})
        },
        u'itemrtdb.question': {
            'Meta': {'object_name': 'Question'},
            'content': ('django.db.models.fields.TextField', [], {'max_length': '2000'}),
            'difficulty': ('django.db.models.fields.IntegerField', [], {}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'marks': ('django.db.models.fields.DecimalField', [], {'max_digits': '3', 'decimal_places': '1'}),
            'meta': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['itemrtdb.Meta']", 'through': u"orm['itemrtdb.QuestionMeta']", 'symmetrical': 'False'}),
            'time': ('django.db.models.fields.IntegerField', [], {}),
            'topic': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['itemrtdb.Topic']"}),
            'type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['itemrtdb.Type']"})
        },
        u'itemrtdb.questionmeta': {
            'Meta': {'object_name': 'QuestionMeta'},
            'content': ('django.db.models.fields.CharField', [], {'max_length': '50'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'meta': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['itemrtdb.Meta']"}),
            'question': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['itemrtdb.Question']"})
        },
        u'itemrtdb.response': {
            'Meta': {'object_name': 'Response'},
            'ability': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '5', 'decimal_places': '2'}),
            'assessment': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['itemrtdb.Assessment']"}),
            'correctness': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '3', 'decimal_places': '2'}),
            'criterion': ('django.db.models.fields.DecimalField', [], {'max_digits': '3', 'decimal_places': '1'}),
            'date': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'duration': ('django.db.models.fields.IntegerField', [], {'null': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'question': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['itemrtdb.Question']"}),
            'response': ('django.db.models.fields.TextField', [], {'max_length': '100'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']"})
        },
        u'itemrtdb.solution': {
            'Meta': {'object_name': 'Solution'},
            'content': ('django.db.models.fields.TextField', [], {'max_length': '2000'}),
            'question': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "'solution'", 'unique': 'True', 'primary_key': 'True', 'to': u"orm['itemrtdb.Question']"}),
            'rating': ('django.db.models.fields.IntegerField', [], {})
        },
        u'itemrtdb.test': {
            'Meta': {'object_name': 'Test'},
            'generated': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.CharField', [], {'max_length': '6', 'primary_key': 'True'}),
            'questions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['itemrtdb.Question']", 'through': u"orm['itemrtdb.TestQuestion']", 'symmetrical': 'False'}),
            'state': ('django.db.models.fields.BooleanField', [], {'default': 'False'})
        },
        u'itemrtdb.testquestion': {
            'Meta': {'object_name': 'TestQuestion'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'question': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['itemrtdb.Question']"}),
            'test': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['itemrtdb.Test']"})
        },
        u'itemrtdb.testresponse': {
            'Meta': {'object_name': 'TestResponse', '_ormbases': [u'itemrtdb.Response']},
            u'response_ptr': ('django.db.models.fields.related.OneToOneField', [], {'to': u"orm['itemrtdb.Response']", 'unique': 'True', 'primary_key': 'True'}),
            'test': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "'responses'", 'to': u"orm['itemrtdb.Test']"})
        },
        u'itemrtdb.topic': {
            'Meta': {'object_name': 'Topic'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '30'})
        },
        u'itemrtdb.type': {
            'Meta': {'object_name': 'Type'},
            'description': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        }
    }

    complete_apps = ['itemrtdb']