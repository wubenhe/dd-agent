"""kubernetes check
Collects metrics from cAdvisor instance
"""
# stdlib
from collections import defaultdict
from fnmatch import fnmatch
import numbers
import re
import simplejson as json

# 3rd party
import requests

# project
from checks import AgentCheck
from config import _is_affirmative
from utils.http import retrieve_json
from utils.kubeutil import KubeUtil

NAMESPACE = "kubernetes"
DEFAULT_MAX_DEPTH = 10

DEFAULT_USE_HISTOGRAM = False
DEFAULT_PUBLISH_ALIASES = False
DEFAULT_ENABLED_RATES = [
    'diskio.io_service_bytes.stats.total',
    'network.??_bytes',
    'cpu.*.total']

NET_ERRORS = ['rx_errors', 'tx_errors', 'rx_dropped', 'tx_dropped']

DEFAULT_ENABLED_GAUGES = [
    'memory.usage',
    'filesystem.usage']

GAUGE = AgentCheck.gauge
RATE = AgentCheck.rate
HISTORATE = AgentCheck.generate_historate_func(["container_name"])
HISTO = AgentCheck.generate_histogram_func(["container_name"])
FUNC_MAP = {
    GAUGE: {True: HISTO, False: GAUGE},
    RATE: {True: HISTORATE, False: RATE}
}

BLACKLISTED_LABELS = set([
    "io.kubernetes.pod.terminationGracePeriod",
    "io.kubernetes.container.hash",
    "io.kubernetes.container.restartCount",
    "io.kubernetes.container.terminationMessagePath",
    "io.kubernetes.pod.uid",

    # Those below will be processed separately
    "io.kubernetes.pod.name",
    "io.kubernetes.pod.namespace",

])


class Kubernetes(AgentCheck):
    """ Collect metrics and events from kubelet """

    pod_names_by_container = {}

    def __init__(self, name, init_config, agentConfig, instances=None):
        if instances is not None and len(instances) > 1:
            raise Exception('Kubernetes check only supports one configured instance.')
        AgentCheck.__init__(self, name, init_config, agentConfig, instances)
        self.kubeutil = KubeUtil()

    def _perform_kubelet_checks(self, url):
        service_check_base = NAMESPACE + '.kubelet.check'
        is_ok = True
        try:
            r = requests.get(url)
            for line in r.iter_lines():

                # avoid noise; this check is expected to fail since we override the container hostname
                if line.find('hostname') != -1:
                    continue

                matches = re.match('\[(.)\]([^\s]+) (.*)?', line)
                if not matches or len(matches.groups()) < 2:
                    continue

                service_check_name = service_check_base + '.' + matches.group(2)
                status = matches.group(1)
                if status == '+':
                    self.service_check(service_check_name, AgentCheck.OK)
                else:
                    self.service_check(service_check_name, AgentCheck.CRITICAL)
                    is_ok = False

        except Exception, e:
            self.log.warning('kubelet check failed: %s' % str(e))
            self.service_check(service_check_base, AgentCheck.CRITICAL,
                               message='Kubelet check failed: %s' % str(e))

        else:
            if is_ok:
                self.service_check(service_check_base, AgentCheck.OK)
            else:
                self.service_check(service_check_base, AgentCheck.CRITICAL)

    def _perform_master_checks(self, url):
        try:
            r = requests.get(url)
            r.raise_for_status()
            for nodeinfo in r.json()['items']:
                nodename = nodeinfo['name']
                service_check_name = "{0}.master.{1}.check".format(NAMESPACE, nodename)
                cond = nodeinfo['status'][-1]['type']
                minion_name = nodeinfo['metadata']['name']
                tags = ["minion_name:{0}".format(minion_name)]
                if cond != 'Ready':
                    self.service_check(service_check_name, AgentCheck.CRITICAL,
                                       tags=tags, message=cond)
                else:
                    self.service_check(service_check_name, AgentCheck.OK, tags=tags)
        except Exception, e:
            self.service_check(service_check_name, AgentCheck.CRITICAL, message=str(e))
            self.log.warning('master checks url=%s exception=%s' % (url, str(e)))
            raise

    def check(self, instance):
        if not self.kubeutil.host:
            raise Exception('Unable to get default router and host parameter is not set')

        self.max_depth = instance.get('max_depth', DEFAULT_MAX_DEPTH)
        enabled_gauges = instance.get('enabled_gauges', DEFAULT_ENABLED_GAUGES)
        self.enabled_gauges = ["{0}.{1}".format(NAMESPACE, x) for x in enabled_gauges]
        enabled_rates = instance.get('enabled_rates', DEFAULT_ENABLED_RATES)
        self.enabled_rates = ["{0}.{1}".format(NAMESPACE, x) for x in enabled_rates]

        self.publish_aliases = _is_affirmative(instance.get('publish_aliases', DEFAULT_PUBLISH_ALIASES))
        self.use_histogram = _is_affirmative(instance.get('use_histogram', DEFAULT_USE_HISTOGRAM))
        self.publish_rate = FUNC_MAP[RATE][self.use_histogram]
        self.publish_gauge = FUNC_MAP[GAUGE][self.use_histogram]

        # master health checks
        if instance.get('enable_master_checks', False):
            self._perform_master_checks(self.kubeutil.master_url_nodes)

        # kubelet health checks
        if instance.get('enable_kubelet_checks', True):
            self._perform_kubelet_checks(self.kubeutil.kube_health_url)

        # kubelet metrics
        self._update_metrics(instance)

    def _publish_raw_metrics(self, metric, dat, tags, depth=0):
        if depth >= self.max_depth:
            self.log.warning('Reached max depth on metric=%s' % metric)
            return

        if isinstance(dat, numbers.Number):
            if self.enabled_rates and any([fnmatch(metric, pat) for pat in self.enabled_rates]):
                self.publish_rate(self, metric, float(dat), tags)
            elif self.enabled_gauges and any([fnmatch(metric, pat) for pat in self.enabled_gauges]):
                self.publish_gauge(self, metric, float(dat), tags)

        elif isinstance(dat, dict):
            for k, v in dat.iteritems():
                self._publish_raw_metrics(metric + '.%s' % k.lower(), v, tags, depth + 1)

        elif isinstance(dat, list):
            self._publish_raw_metrics(metric, dat[-1], tags, depth + 1)

    @staticmethod
    def _shorten_name(name):
        # shorten docker image id
        return re.sub('([0-9a-fA-F]{64,})', lambda x: x.group(1)[0:12], name)

    def _get_post_1_2_tags(self, tags, cont_labels, subcontainer, kube_labels):

        pod_name = cont_labels["io.kubernetes.pod.name"]
        pod_namespace = cont_labels["io.kubernetes.pod.namespace"]
        tags.append("pod_name:{0}".format(pod_name))
        tags.append("kube_namespace:{0}".format(pod_namespace))

        kube_labels_key = "{0}/{1}".format(pod_namespace, pod_name)
        pod_labels = kube_labels.get(kube_labels_key)
        if pod_labels:
            tags.extend(list(pod_labels))

        if "-" in pod_name:
            replication_controller = "-".join(pod_name.split("-")[:-1])
            tags.append("kube_replication_controller:%s" % replication_controller)

        if self.publish_aliases and subcontainer.get("aliases"):
            for alias in subcontainer['aliases'][1:]:
                    # we don't add the first alias as it will be the container_name
                    tags.append('container_alias:%s' % (self._shorten_name(alias)))

        return tags

    def _get_pre_1_2_tags(self, tags, cont_labels, subcontainer, kube_labels):

        pod_name = cont_labels["io.kubernetes.pod.name"]
        tags.append("pod_name:{0}".format(pod_name))
        pod_labels = kube_labels.get(pod_name)
        if pod_labels:
            tags.extend(list(pod_labels))

        if "-" in pod_name:
            replication_controller = "-".join(pod_name.split("-")[:-1])
            if "/" in replication_controller:
                namespace, replication_controller = replication_controller.split("/", 1)
                tags.append("kube_namespace:%s" % namespace)

            tags.append("kube_replication_controller:%s" % replication_controller)

        if self.publish_aliases and subcontainer.get("aliases"):
            for alias in subcontainer['aliases'][1:]:
                    # we don't add the first alias as it will be the container_name
                    tags.append('container_alias:%s' % (self._shorten_name(alias)))

        return tags


    def _update_container_metrics(self, instance, subcontainer, kube_labels):
        tags = instance.get('tags', [])  # add support for custom tags

        if len(subcontainer.get('aliases', [])) >= 1:
            # The first alias seems to always match the docker container name
            container_name = subcontainer['aliases'][0]
        else:
            # We default to the container id
            container_name = subcontainer['name']

        tags.append('container_name:%s' % container_name)


        try:
            cont_labels = subcontainer['spec']['labels']
        except KeyError:
            self.log.debug("Subcontainer, doesn't have any labels")
            cont_labels = {}

        for label_name, label in cont_labels.iteritems():
            if label_name in BLACKLISTED_LABELS:
                self.log.debug("Skipping label: {0}={1}".format(label_name, label))
                continue
            tags.append('%s:%s' % (label_name, label))

        # Collect pod names, namespaces, rc...

        if "io.kubernetes.pod.namespace" in cont_labels and "io.kubernetes.pod.name" in cont_labels:
            # Kubernetes >= 1.2
            tags = self._get_post_1_2_tags(tags, cont_labels, subcontainer, kube_labels)

        elif "io.kubernetes.pod.name" in cont_labels:
            # Kubernetes <= 1.1
            tags = self._get_pre_1_2_tags(tags, cont_labels, subcontainer, kube_labels)

        else:
            # Those are containers that are not part of a pod.
            # They are top aggregate views and don't have the previous metadata.
            tags.append("pod_name:no_pod")


        stats = subcontainer['stats'][-1]  # take the latest
        self._publish_raw_metrics(NAMESPACE, stats, tags)

        if subcontainer.get("spec", {}).get("has_filesystem"):
            fs = stats['filesystem'][-1]
            fs_utilization = float(fs['usage'])/float(fs['capacity'])
            self.publish_gauge(self, NAMESPACE + '.filesystem.usage_pct', fs_utilization, tags)

        if subcontainer.get("spec", {}).get("has_network"):
            net = stats['network']
            self.publish_rate(self, NAMESPACE + '.network_errors',
                              sum(float(net[x]) for x in NET_ERRORS),
                              tags)

    def _retrieve_metrics(self, url):
        return retrieve_json(url)

    def _update_metrics(self, instance):
        pods_list = self.kubeutil.retrieve_pods_list()
        metrics = self._retrieve_metrics(self.kubeutil.metrics_url)
        kube_labels = self.kubeutil.extract_kube_labels(pods_list)

        if not metrics:
            raise Exception('No metrics retrieved cmd=%s' % self.metrics_cmd)

        for subcontainer in metrics:
            try:
                self._update_container_metrics(instance, subcontainer, kube_labels)
            except Exception, e:
                self.log.error("Unable to collect metrics for container: {0} ({1}".format(
                    subcontainer.get('name'), e))

        self._update_pods_metrics(instance, pods_list)

    def _update_pods_metrics(self, instance, pods):
        controllers_map = defaultdict(list)
        for pod in pods['items']:
            node_name = pod['spec']['nodeName']
            try:
                created_by = json.loads(pod['metadata']['annotations']['kubernetes.io/created-by'])
                if created_by['reference']['kind'] == 'ReplicationController':
                    controllers_map[created_by['reference']['name']].append(node_name)
            except KeyError:
                continue

        tags = instance.get('tags', [])
        for ctrl, pods in controllers_map.iteritems():
            _tags = tags[:]  # copy base tags
            _tags.append('kube_replication_controller:{0}'.format(ctrl))
            self.publish_gauge(self, NAMESPACE + '.pods.running', len(pods), _tags)
