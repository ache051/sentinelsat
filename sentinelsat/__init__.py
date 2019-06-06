__version__ = '0.14'

# Import for backwards-compatibility
from . import sentinel

from .sentinel import  SentinelAPI, format_query_date, geojson_to_wkt, read_geojson
from .error import InvalidChecksumError, SentinelAPIError, SentinelAPILTAError
