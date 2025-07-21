from django import forms


class EntityForm(forms.Form):
    entity = forms.CharField(label="entity")
