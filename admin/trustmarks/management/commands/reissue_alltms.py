import djclick as click
from django_redis import get_redis_connection
from trustmarks.lib import add_trustmark
from trustmarks.models import TrustMark


@click.command()
def command():
    "Reissues TrustMarks for activated entities from the Database."
    con = get_redis_connection("default")
    tms = TrustMark.objects.all()
    for tm in tms:
        if tm.active:
            # Means we can reissue this one
            add_trustmark(tm.domain, tm.tmt.tmtype, con)
            click.secho(f"Reissued {tm.domain}")
