# pdns/notifiers/mattermost/notifier.py
from ..webhook import WebhookNotifier
from ..filters.base import NotificationFilter


class MattermostNotifier(WebhookNotifier):
    """Notifier that sends alerts to Mattermost via webhook."""

    type = 'mattermost'

    def __init__(
        self,
        config: dict,
        filter_instance: NotificationFilter,
        template_dir: str,
    ):
        """Initialize the Mattermost notifier.

        Args:
            config (dict): Configuration with 'webhook_url'.
            filter_instance (NotificationFilter): Filter to evaluate records.
            template_dir (str): Directory for default templates.
        """
        super().__init__(config, filter_instance, template_dir)