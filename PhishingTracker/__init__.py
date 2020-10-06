
analyzers_available = ['dig', 'http', 'https', 'https_certificate', 'smtp', 'whois', 'safe_browsing']
analyzer_action_timeout = 10

from .__name__ import NAME
from .__version__ import VERSION

from .exceptions import PhishingTrackerException
from .logger import PhishingTrackerLogger

from .file import PhishingTrackerFile
from .meta import PhishingTrackerMeta

from .certificate import PhishingTrackerCertificate
from .dig import PhishingTrackerDig
from .smtp import PhishingTrackerSmtp
from .web import PhishingTrackerWeb
from .whois import PhishingTrackerWhois
from .safebrowsing import PhishingTrackerSafeBrowsing

from .analyzers import PhishingTrackerAnalyzers
from .tests import PhishingTrackerTests

from .main import PhishingTracker
