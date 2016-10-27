from functools import total_ordering


@total_ordering
class Label:
    def __init__(self, attack_name, timestamp_start, timestamp_end, attack_note=""):
        """
        Creates a new attack label

        :param attack_name: The name of the associated attack
        :param timestamp_start: The timestamp as unix time of the first attack packet
        :param timestamp_end: The timestamp as unix time of the last attack packet
        :param attack_note: A note associated to the attack (optional)
        """
        self.attack_name = attack_name
        self.timestamp_start = timestamp_start
        self.timestamp_end = timestamp_end
        self.attack_note = attack_note

    def __eq__(self, other):
        return self.timestamp == other.timestamp

    def __lt__(self, other):
        return self.timestamp_start < other.timestamp_start

    def __gt__(self, other):
        return self.timestamp_start > other.timestamp_start

    def __str__(self):
        return ''.join(
            ['(', self.attack_name, ',', self.attack_note, ',', str(self.timestamp_start), ',', str(self.timestamp_end),
             ')'])
