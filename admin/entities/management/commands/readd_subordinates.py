import djclick as click
from django_redis import get_redis_connection
from entities.lib import add_subordinate
from entities.models import Subordinate


@click.command()
def command():
    "Readds all subordinates from the Database."
    con = get_redis_connection("default")
    # First clean up the existing HashMap in redis
    con.delete("inmor:subordinates")
    subs = Subordinate.objects.all()
    for sub in subs:
        # Means we can reissue this one
        add_subordinate(sub.entityid, con)
        click.secho(f"Reissued {sub.entityid}")
