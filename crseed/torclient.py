import base64
from datetime import datetime
import glob, os
import qbittorrentapi
import transmission_rpc
import requests
import deluge_client
import logging
import pytz
import time
import re
import urllib.parse
from abc import abstractmethod, ABCMeta

logger = logging.getLogger(__name__)


def getDownloadClient(scsetting, log=None):
    if scsetting.clienttype == 'qb':
        scobj = QbDownloadClient(scsetting, log)
    elif scsetting.clienttype == 'tr':
        scobj = TrDownloadClient(scsetting, log)
    elif scsetting.clienttype == 'de':
        scobj = DeDownloadClient(scsetting, log)
    elif scsetting.clienttype == 'rt':
        scobj = RtDownloadClient(scsetting, log)
    return scobj


class DownloadClientBase(metaclass=ABCMeta):
    def __init__(self, scsetting, log=None):
        self.scsetting = scsetting
        self.logger = log

    @abstractmethod
    def connect(self):
        pass

    def log(self, msg):
        if self.logger:
            self.logger.message(msg)
        logger.debug(msg)


class TrDownloadClient(DownloadClientBase):
    def __init__(self, scsetting, log=None):
        self.scsetting = scsetting
        self.trClient = None
        self.logger = log

    def connect(self):
        self.trClient = None
        try:
            self.trClient = transmission_rpc.Client(
                host=self.scsetting.host,
                port=self.scsetting.port,
                username=self.scsetting.username,
                password=self.scsetting.password)
        except transmission_rpc.error.TransmissionError as e:
            self.log("TransmissionError: check settings")
            return None

        return self.trClient

    def mkSeedTor(self, trTor):
        if not trTor:
            return None
        st = SeedingTorrent(
            torrent_hash=trTor.hashString,
            name=trTor.name,
            size=trTor.total_size,
            tracker=self.abbrevTracker(trTor.trackers[0]),
            added_date=trTor.date_added,
            status=trTor.status,
            save_path=trTor.download_dir,
        )
        return st

    def abbrevTracker(self, trackerJson):
        hostnameList = urllib.parse.urlparse(
            trackerJson["announce"]).netloc.split('.')
        if len(hostnameList) == 2:
            abbrev = hostnameList[0]
        elif len(hostnameList) == 3:
            abbrev = hostnameList[1]
        else:
            abbrev = ''
        return abbrev

    def loadTorrents(self):
        self.trClient = self.connect()
        if not self.trClient:
            return []
        torList = self.trClient.get_torrents(arguments=[
            'id', 'name', 'hashString', 'downloadDir', 'totalSize', 'trackers',
            'addedDate', 'status'
        ])
        activeList = []
        for trTor in torList:
            st = self.mkSeedTor(trTor)
            activeList.append(st)
        return activeList

    def addTorrentUrl(self, tor_url, download_location, tor_title):
        if not self.trClient:
            self.connect()
        newtor = None
        if self.trClient:
            try:
                newtor = self.trClient.add_torrent(
                    tor_url, paused=True, download_dir=download_location)
            except Exception as e:
                self.log('Torrent not added. Torrent already in session..')
                return None

        return self.getTorrent(newtor.hashString)

    def getTorrent(self, tor_hash):
        try:
            logger.info('Double checking that the torrent was added.')
            trTor = self.trClient.get_torrent(tor_hash,
                                              arguments=[
                                                  'id', 'name', 'hashString',
                                                  'downloadDir', 'totalSize',
                                                  'trackers', 'addedDate',
                                                  'status'
                                              ])

        except Exception as e:
            self.log('Torrent was not added! maybe exists.')
            return None
        else:
            if trTor:
                self.log('Torrent added!')
                st = self.mkSeedTor(trTor)
                return st
            else:
                self.log('Torrent not added! Maybe exists.')
                return None


class QbDownloadClient(DownloadClientBase):
    def __init__(self, scsetting, log=None):
        self.scsetting = scsetting
        self.qbClient = None
        self.logger = log

    def connect(self):
        self.qbClient = qbittorrentapi.Client(
            host=self.scsetting.host,
            port=self.scsetting.port,
            username=self.scsetting.username,
            password=self.scsetting.password,
            #   VERIFY_WEBUI_CERTIFICATE = False,
        )
        try:
            self.qbClient.auth_log_in()
        except Exception as ex:
            self.log('There was an error during auth_log_in: ' + repr(ex))
            return None

        return self.qbClient


    # def abbrevTracker(self, trackerstr):
    #     hostnameList = urllib.parse.urlparse(trackerstr).netloc.split('.')
    #     if len(hostnameList) == 2:
    #         abbrev = hostnameList[0]
    #     elif len(hostnameList) == 3:
    #         abbrev = hostnameList[1]
    #     else:
    #         abbrev = ''
    #     return abbrev

    def abbrevTracker(self, trackerstr):
        if len(trackerstr) < 2:
            return ''
        hostnameList = urllib.parse.urlparse(trackerstr).netloc.split('.')
        if len(hostnameList) == 2:
            abbrev = hostnameList[0]
        elif len(hostnameList) == 3:
            abbrev = hostnameList[1]
        else:
            abbrev = ''
        return abbrev

    def mkSeedTor(self, tor):
        ltr = 3 if len(tor.trackers) >= 4 else (len(tor.trackers) -1)
        if len(tor.trackers) < 4:
            print("The Trackers", tor.trackers)
        if ltr > 0:
            trackerstr = tor.tracker if len(tor.tracker)>1 else tor.trackers[ltr]["url"]
        else:
            print("No tracker string")
            trackerstr = 'unknow'
        st = SeedingTorrent(
            torrent_hash=tor.hash,
            name=tor.name,
            size=tor.size,
            tracker=self.abbrevTracker(trackerstr),
            added_date=datetime.utcfromtimestamp(
                tor.added_on).replace(tzinfo=pytz.utc),
            status=tor.state,
            save_path=tor.save_path,
        )
        return st

    def loadTorrents(self):
        if not self.qbClient:
            self.connect()
        if not self.qbClient:
            return []

        torList = self.qbClient.torrents_info()
        activeList = []
        for qbTor in torList:
            st = self.mkSeedTor(qbTor)
            activeList.append(st)
        return activeList

    def cutExt(self, torName):
        if not torName:
            return ''
        tortup = os.path.splitext(torName)
        torext = tortup[1].lower()
        if re.match(r'\.[0-9a-z]{2,8}$', torext, flags=re.I):
            return tortup[0].strip()
        else:
            return torName

    def normalizeTorTitle(self, torTitle):
        torTitle = self.cutExt(torTitle)
        return re.sub(r'\.', ' ', torTitle)

    def findJustAdded(self, timestamp):
        time.sleep(3)
        # torList = self.qbClient.torrents_info(sort='added_on', limit=1, reverse=True, tag=timestamp)
        torList = self.qbClient.torrents_info(category=timestamp)
        # breakpoint()
        if torList:
            print('Added: '+torList[0].name)
            # torList[0].set_category(category=None)
            # time.sleep(1)
            self.qbClient.torrents_remove_categories(categories=timestamp)
            return torList[0]
        else:
            time.sleep(1)
            self.qbClient.torrents_remove_categories(categories=timestamp)
            torList = self.qbClient.torrents_info(sort='added_on')
            # torList = self.qbClient.torrents_info(status_filter='paused', sort='added_on')
            if torList:
                print('Not Added.')
                return None
            else:
                return torList[-1] if torList else None


    def addTorrentUrl(self, tor_url, download_location, tor_title):
        if not self.qbClient:
            self.connect()
        st = None
        if self.qbClient:
            try:
                # curr_added_on = time.time()
                timestamp = str(int(time.time()))
                result = self.qbClient.torrents_add(
                    urls=tor_url,
                    is_paused=True,
                    save_path=download_location,
                    use_auto_torrent_management=False,
                    category=timestamp,
                    # tags=[timestamp],
                    download_path=download_location )
                # breakpoint()
                if 'OK' in result.upper():
                    qbTor = self.findJustAdded(timestamp)
                    if qbTor:
                        st = self.mkSeedTor(qbTor)
                    else:
                        self.log('Torrent not added! Maybe exists.')
                else:
                    self.log('Torrent not added! something wrong with qb api ...')
            except Exception as e:
                self.log('Torrent not added! Torrent already in session.')
                return None

        return st

    def getTorrent(self, tor_hash):
        try:
            logger.info('Double checking that the torrent was added.')
            qbTor = self.qbClient.torrents_info(torrent_hashes=tor_hash)
        except Exception as e:
            logger.warn('Torrent was not added! ')
            return None
        else:
            if qbTor:
                self.log('Torrent added!')
                st = self.mkSeedTor(qbTor)
                return st
            else:
                self.log('Torrent not added! Maybe exists.')
                return None


class DeDownloadClient(DownloadClientBase):
    def __init__(self, scsetting, log=None):
        self.scsetting = scsetting
        self.deClient = None
        self.logger = log

    def connect(self):
        if self.scsetting is None:
            return None

        self.log('Connecting to ' + self.scsetting.host + ':' + str(self.scsetting.port))
        try:
            self.deClient = deluge_client.DelugeRPCClient(
                self.scsetting.host, int(self.scsetting.port),
                self.scsetting.username, self.scsetting.password)
        except Exception as e:
            self.log('Could not create DelugeRPCClient Object...')
            return None
        else:
            try:
                self.deClient.connect()
            except Exception as e:
                self.log('Could not connect to Deluge ' + self.scsetting.host)
            else:
                return self.deClient

    def mkSeedTor(self, deTor):
        savePath = deTor[b'download_path'].decode("utf-8") if hasattr(deTor, 'download_path') else deTor[b'save_path'].decode("utf-8")
        # savePath = deTor[b'save_path'].decode("utf-8")
        st = SeedingTorrent(
            torrent_hash=deTor[b'hash'].decode("utf-8"),
            name=deTor[b'name'].decode("utf-8"),
            size=deTor[b'total_size'],
            tracker=self.abbrevTracker(deTor[b'tracker_host'].decode("utf-8")),
            added_date=datetime.utcfromtimestamp(
                deTor[b'time_added']).replace(tzinfo=pytz.utc),
            status=deTor[b'state'].decode("utf-8"),
            save_path=savePath,
        )
        return st

    def getTorrent(self, tor_hash):
        try:
            self.log('Double checking that the torrent was added.')

            # deTor1 = self.get_torrent(tor_hash)
            deTor = self.deClient.call('core.get_torrent_status', tor_hash, [
                'name', 'hash', 'download_location', 'save_path', 'total_size',
                'tracker_host', 'time_added', 'state'
            ])

        except Exception as e:
            self.log('Torrent was not added, Torrent already in session')
            return None
        else:
            if deTor:
                self.log('Torrent added!')
                st = self.mkSeedTor(deTor)
                return st
            else:
                self.log('Torrent was not added! maybe exists.')
                return None

    def addTorrentUrl(self, tor_url, download_location, tor_title):
        if not self.deClient:
            self.connect()
        torhash = None
        if self.deClient:
            t_options = {}
            t_options['add_paused'] = True
            t_options['save_path'] = download_location
            t_options['download_location'] = download_location
            try:
                torid = self.deClient.call('core.add_torrent_url', tor_url,
                                           t_options)
                torhash = torid.decode("utf-8")

            except Exception as e:
                self.log('Torrent not added, Torrent already in session.')
                return None

        return self.getTorrent(torhash)

    def add_torrent_file(self, filepath, download_location):
        if not self.deClient:
            self.connect()
        torrent_id = False

        if self.deClient:
            # logger.info('Checking if Torrent Exists!')

            torrentcontent = open(filepath, 'rb').read()
            # Deluge expects a lower case hash
            #            hash = str.lower(self.get_the_hash(filepath))

            #            logger.debug('Torrent Hash (load_torrent): "' + hash + '"')
            self.log('FileName (load_torrent): ' + str(os.path.basename(filepath)))

            t_options = {}
            t_options['add_paused'] = True
            t_options['save_path'] = download_location
            t_options['download_location'] = download_location
            try:
                torrent_id = self.deClient.call(
                    'core.add_torrent_file', str(os.path.basename(filepath)),
                    base64.encodestring(torrentcontent), t_options)
            except Exception as e:
                self.log('Torrent not added, Torrent already in session.')
                return None

        return self.getTorrent(torrent_id)

    def find_torrent(self, hash):
        logger.debug('Finding Torrent hash: ' + hash)
        torrent_info = self.getTorrent(hash)
        if torrent_info:
            return True
        else:
            return False

    def abbrevTracker(self, trackerHost):
        if len(trackerHost) < 2:
            return ''
        hostnameList = trackerHost.split('.')
        if len(hostnameList) == 2:
            abbrev = hostnameList[0]
        elif len(hostnameList) == 3:
            abbrev = hostnameList[1]
        else:
            abbrev = ''
        return abbrev

    def loadTorrents(self):
        if not self.deClient:
            self.connect()
        if not self.deClient:
            return []
        torList = self.deClient.call(
            'core.get_torrents_status', {"state": "Seeding"}, [
                'name', 'hash', 'download_location', 'save_path', 'total_size',
                'tracker_host', 'time_added', 'state'
            ])
        activeList = []
        for deTor in torList.values():
            st = self.mkSeedTor(deTor)
            activeList.append(st)
        return activeList


class RtDownloadClient(DownloadClientBase):


    def __call_server(self, url, data=None, files=None, header=None):
        response = requests.post(url, data=data if data is not None else {}, files=files, headers=header or self.header)
        return response.json() if 'application/json' in response.headers.get('Content-Type') else response


    def __init__(self, scsetting, log=None):
        self.__cpu_load_path = "/plugins/cpuload/action.php"
        self.__disk_size_path = "/plugins/diskspace/action.php"
        self.__default_path = "/plugins/httprpc/action.php"
        self.__upload_torrent_path = "/php/addtorrent.php"
        self.__connection_check_path = "/plugins/check_port/action.php?init"


        self.scsetting = scsetting
        self.logger = log
        self.path = "/" # read this from UI for handling https://mymediaserver.com/rutorrent ( `/rutorrent` will be the path )
        self.base_url = f'{"http" if self.scsetting.port != 443 else "https"}://{self.scsetting.host}:{self.scsetting.port}{self.path}'
        self.header = {}
        if self.scsetting.username:
            hashed = base64.b64encode(f"{self.scsetting.username}:{self.scsetting.password if self.scsetting.password is not None else ''}"
                .encode('ascii')).decode('ascii')
            self.header = {"Authorization": f"Basic {hashed}"}


    def connect(self):
        try:
            self.__call_server(f'{self.base_url}{self.__connection_check_path}')
            return True
        except Exception as err:
            return None


    def abbrevTracker(self, trackerstr):
        hostnameList = urllib.parse.urlparse(trackerstr).netloc.split('.')
        if len(hostnameList) == 2:
            abbrev = hostnameList[0]
        elif len(hostnameList) == 3:
            abbrev = hostnameList[1]
        else:
            abbrev = 'NO_TRACKER'
        return abbrev


    def __get_torrent_info(self, item):
        key = item[0]
        data = item[1]
        return {
            'hash': key,
            'd.is_open': data[0],
            'd.is_hash_checking': data[1],
            'd.is_hash_checked': data[2],
            'd.get_state': data[3],
            'd.get_name': data[4],
            'd.get_size_bytes': data[5],
            'd.get_completed_chunks': data[6],
            'd.get_size_chunks': data[7],
            'd.get_bytes_done': data[8],
            'd.get_up_total': data[9],
            'd.get_ratio': data[10],
            'd.get_up_rate': data[11],
            'd.get_down_rate': data[12],
            'd.get_chunk_size': data[13],
            'd.get_custom1': data[14],
            'd.get_peers_accounted': data[15],
            'd.get_peers_not_connected': data[16],
            'd.get_peers_connected': data[17],
            'd.get_peers_complete': data[18],
            'd.get_left_bytes': data[19],
            'd.get_priority': data[20],
            'd.get_state_changed': data[21],
            'd.get_skip_total': data[22],
            'd.get_hashing': data[23],
            'd.get_chunks_hashed': data[24],
            'd.get_base_path': data[25],
            'd.get_creation_date': data[26],
            'd.get_tracker_focus': data[27],
            'd.is_active': data[28],
            'd.get_message': data[29],
            'd.get_custom2': data[30],
            'd.get_free_diskspace': data[31],
            'd.is_private': data[32],
            'd.is_multi_file': data[33]
        }


    def __extract_necessary_keys(self, torrent):
        torrent = {self.__do_key_translation(key): value for key, value in torrent.items() if key in self.__rutorrent_keys}
        return torrent


    def mkSeedTor(self, tor):
        return SeedingTorrent(
            torrent_hash = tor["hash"],
            name = tor["d.get_name"],
            size = int(tor["d.get_size_bytes"]),
            tracker = "NO_TRACKER",
            added_date = tor["d.get_creation_date"],
            status = tor["d.get_state"],
            save_path = tor["d.get_base_path"].replace(tor["d.get_name"], ""),
        )


    def loadTorrents(self):
        response = self.__call_server(f'{self.base_url}{self.__default_path}', data={'mode': 'list'})
        if isinstance(response["t"], list):
            return []
        torrents = list(map(self.mkSeedTor, map(self.__get_torrent_info, response["t"].items())))
        response = self.__call_server(f'{self.base_url}{self.__default_path}', data={'mode': 'trkall'})
        if isinstance(response, dict):
            for torrent in torrents:
                try:
                    torrent.tracker= self.abbrevTracker(response[torrent.torrent_hash][0][0])
                except Exception as ex:
                    torrent.tracker = "NO_TRACKER"
        return torrents


    def findJustAdded(self):
        torrents = self.loadTorrents()
        return sorted(torrents, key=lambda t: t.added_date, reverse=True)[0]


    def addTorrentUrl(self, tor_url, download_location, tor_title):
        self.__call_server(
            f'{self.base_url}{self.__upload_torrent_path}',
            data={
                "url": tor_url,
                "torrents_start_stopped": "1",
                "label": "SeedCross",
                "dir_edit": download_location
            }
        )
        # allowing torrent client to download and add the torrent
        time.sleep(5)
        return self.findJustAdded()


class SeedingTorrent(object):
    def __init__(self, torrent_hash, name, size, tracker, added_date, status,
                 save_path):
        self.torrent_hash = torrent_hash
        self.name = name
        self.size = size
        self.tracker = tracker
        self.added_date = added_date
        self.status = status
        self.save_path = save_path
