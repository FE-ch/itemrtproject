# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Assessment'
        db.create_table(u'itemrtdb_assessment', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=30)),
            ('type', self.gf('django.db.models.fields.CharField')(max_length=1)),
            ('active', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('engine', self.gf('django.db.models.fields.CharField')(max_length=30)),
        ))
        db.send_create_signal(u'itemrtdb', ['Assessment'])

        # Adding model 'QuestionMeta'
        db.create_table(u'itemrtdb_questionmeta', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('question', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['itemrtdb.Question'])),
            ('meta', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['itemrtdb.Meta'])),
            ('content', self.gf('django.db.models.fields.CharField')(max_length=50)),
        ))
        db.send_create_signal(u'itemrtdb', ['QuestionMeta'])

        # Adding model 'Question'
        db.create_table(u'itemrtdb_question', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('content', self.gf('django.db.models.fields.TextField')(max_length=2000)),
            ('difficulty', self.gf('django.db.models.fields.IntegerField')()),
            ('topic', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['itemrtdb.Topic'])),
            ('time', self.gf('django.db.models.fields.IntegerField')()),
            ('mark', self.gf('django.db.models.fields.DecimalField')(max_digits=3, decimal_places=1)),
            ('type', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['itemrtdb.Type'])),
        ))
        db.send_create_signal(u'itemrtdb', ['Question'])

        # Adding model 'Response'
        db.create_table(u'itemrtdb_response', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('question', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['itemrtdb.Question'])),
            ('response', self.gf('django.db.models.fields.TextField')(max_length=100)),
            ('date', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
            ('duration', self.gf('django.db.models.fields.IntegerField')(null=True, blank=True)),
            ('correct', self.gf('django.db.models.fields.DecimalField')(null=True, max_digits=3, decimal_places=2)),
            ('criterion', self.gf('django.db.models.fields.DecimalField')(max_digits=3, decimal_places=1)),
            ('ability', self.gf('django.db.models.fields.DecimalField')(null=True, max_digits=6, decimal_places=4)),
            ('assessment', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['itemrtdb.Assessment'])),
        ))
        db.send_create_signal(u'itemrtdb', ['Response'])

        # Adding model 'Topic'
        db.create_table(u'itemrtdb_topic', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=30)),
        ))
        db.send_create_signal(u'itemrtdb', ['Topic'])

        # Adding model 'Solution'
        db.create_table(u'itemrtdb_solution', (
            ('question', self.gf('django.db.models.fields.related.OneToOneField')(to=orm['itemrtdb.Question'], unique=True, primary_key=True)),
            ('content', self.gf('django.db.models.fields.TextField')(max_length=2000)),
            ('rating', self.gf('django.db.models.fields.IntegerField')()),
        ))
        db.send_create_signal(u'itemrtdb', ['Solution'])

        # Adding model 'Meta'
        db.create_table(u'itemrtdb_meta', (
            ('metatag', self.gf('django.db.models.fields.CharField')(max_length=30, primary_key=True)),
        ))
        db.send_create_signal(u'itemrtdb', ['Meta'])

        # Adding model 'Answer'
        db.create_table(u'itemrtdb_answer', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('question', self.gf('django.db.models.fields.related.ForeignKey')(related_name='answers', to=orm['itemrtdb.Question'])),
            ('content', self.gf('django.db.models.fields.TextField')(max_length=100)),
            ('correctness', self.gf('django.db.models.fields.DecimalField')(default=1, max_digits=3, decimal_places=2)),
        ))
        db.send_create_signal(u'itemrtdb', ['Answer'])

        # Adding model 'Type'
        db.create_table(u'itemrtdb_type', (
            (u'id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=50)),
            ('description', self.gf('django.db.models.fields.CharField')(max_length=100)),
        ))
        db.send_create_signal(u'itemrtdb', ['Type'])


    def backwards(self, orm):
        # Deleting model 'Assessment'
        db.delete_table(u'itemrtdb_assessment')

        # Deleting model 'QuestionMeta'
        db.delete_table(u'itemrtdb_questionmeta')

        # Deleting model 'Question'
        db.delete_table(u'itemrtdb_question')

        # Deleting model 'Response'
        db.delete_table(u'itemrtdb_response')

        # Deleting model 'Topic'
        db.delete_table(u'itemrtdb_topic')

        # Deleting model 'Solution'
        db.delete_table(u'itemrtdb_solution')

        # Deleting model 'Meta'
        db.delete_table(u'itemrtdb_meta')

        # Deleting model 'Answer'
        db.delete_table(u'itemrtdb_answer')

        # Deleting model 'Type'
        db.delete_table(u'itemrtdb_type')


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
            'mark': ('django.db.models.fields.DecimalField', [], {'max_digits': '3', 'decimal_places': '1'}),
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
            'ability': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '6', 'decimal_places': '4'}),
            'assessment': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['itemrtdb.Assessment']"}),
            'correct': ('django.db.models.fields.DecimalField', [], {'null': 'True', 'max_digits': '3', 'decimal_places': '2'}),
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
            'question': ('django.db.models.fields.related.OneToOneField', [], {'to': u"orm['itemrtdb.Question']", 'unique': 'True', 'primary_key': 'True'}),
            'rating': ('django.db.models.fields.IntegerField', [], {})
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