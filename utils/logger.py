import logging
import logging.config
import os

import yaml


class Logger:
    __instance__ = None

    def __init__(self):
        """ Constructor.
        """
        if Logger.__instance__ is None:
            Logger.__instance__ = self
        else:
            raise Exception("Logger: You cannot create another Logger class")

    @staticmethod
    def get_instance():
        """ Static method to fetch the current instance.
        """
        if not Logger.__instance__:
            Logger()
        return Logger.__instance__

    @staticmethod
    def load_configuration(config_log_path: os.PathLike | str, def_log_level=logging.INFO):
        try:
            config_yaml = open(config_log_path, 'r')
            log_config = yaml.load(config_yaml.read(), Loader=yaml.FullLoader)
            logging.config.dictConfig(log_config)
        except Exception as exception:
            logging.basicConfig(level=def_log_level)
            logging.warning(str(exception))
            logging.warning("Error loading logging configuration file. Using default logging to console!")

    def format_message(self, level, subcomponent, action_id, action_type, log_code, activity):
        msg = "Subcomponent {} received {} {}. Response: {}, Log code {}".format(subcomponent, action_id, action_type,
                                                                                 activity, str(log_code))
        message = "\n=========================\n"
        message += "Subcomponent: " + subcomponent + "\n"
        message += "Action Identifier: " + action_id + "\n"
        message += "Action Type: " + action_type + "\n"
        message += "Log Code: " + str(log_code) + "\n"
        message += "Activity: " + activity + "\n"
        message += "========================="
        # Add module and resource server IP in the module
        # TODO move out of format_message
        # if self.config["database"]["type"] == "elastic":
        #    elastic_msg = {
        #        "@timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
        #        "msg_criticity": level,
        #        "module": "AUTH_{}".format(self.config["resource_server_endpoint"].split("/")[-1].upper()),
        #        "Subcomponent": subcomponent,
        #        "Action Identifier": action_id,
        #        "Action Type": action_type,
        #        "Log Code": log_code,
        #        "message": activity
        #    }
        #    self.send_to_elastic(elastic_msg)
        return msg

    # TODO enable
    # def send_to_elastic(self, msg):
    #    try:
    #        elastic = ElasticSearch("pep_gsc4eo",
    #                                self.config["database"]["ip"] + ":" + self.config["database"]["port"],
    #                                self.config["database"]["username"],
    #                                self.config["database"]["password"])
    #        elastic.insert(msg)
    #    except Exception as exception:
    #        logging.error(str(exception))
