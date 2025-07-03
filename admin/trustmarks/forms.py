from django import forms

from .models import TrustMarkType

try:

    class TrustMarkForm(forms.Form):
        entity = forms.CharField(label="entity")
        tmt_select = forms.ChoiceField(
            choices=[(x.id, x.tmtype) for x in TrustMarkType.objects.all()]
        )

except:  # Stupid HACK

    class TrustMarkForm(forms.Form):
        entity = forms.CharField(label="entity")
        # HACK: till we find a better solution
        tmt_select = forms.ChoiceField(
            choices=[
                ("0", "0"),
            ]
        )
