"""Petit CLI pour pousser une tâche dans la file depuis la ligne de commande.

Usage :
    python engine/enqueue.py insert_dummy_target http://test.local
"""
import sys
from pathlib import Path

from dotenv import load_dotenv

# Rendre le paquet `engine` importable quand on lance `python engine/enqueue.py`.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
# Charger les URLs côté hôte (localhost) depuis .env avant d'instancier Celery.
load_dotenv(ROOT / ".env")

from engine.celery_app import app  # noqa: E402  (import après load_dotenv)


def main(argv):
    if len(argv) < 1:
        print("usage: python engine/enqueue.py <task_name> [args...]")
        return 1
    task_name, task_args = argv[0], argv[1:]
    result = app.send_task(task_name, args=task_args)
    print(f"enqueued {task_name} args={task_args} -> task_id={result.id}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
