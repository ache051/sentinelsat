# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

import logging
import re
import warnings
from collections import OrderedDict, defaultdict
from datetime import date, datetime
from os import remove, mkdir
from os.path import basename, exists, getsize, join, splitext

import geojson
import geomet.wkt
import html2text
import requests
from six import string_types
from six.moves.urllib.parse import urljoin, quote_plus
from tqdm import tqdm

from . import __version__ as sentinelsat_version
from .product import Product
from .error import SentinelAPIError, SentinelAPILTAError, InvalidChecksumError
from .utils import _parse_iso_date, _parse_odata_response, _parse_opensearch_response, _format_query, _format_order_by


class SentinelAPI:
    """Class to connect to Copernicus Open Access Hub, search and download imagery.

    Parameters
    ----------
    user : string
        username for DataHub
        set to None to use ~/.netrc
    password : string
        password for DataHub
        set to None to use ~/.netrc
    api_url : string, optional
        URL of the DataHub
        defaults to 'https://scihub.copernicus.eu/apihub'
    show_progressbars : bool
        Whether progressbars should be shown or not, e.g. during download. Defaults to True.
    timeout : float or tuple, optional
        How long to wait for DataHub response (in seconds).
        Tuple (connect, read) allowed.

    Attributes
    ----------
    session : requests.Session
        Session to connect to DataHub
    api_url : str
        URL to the DataHub
    page_size : int
        Number of results per query page.
        Current value: 100 (maximum allowed on ApiHub)
    timeout : float or tuple
        How long to wait for DataHub response (in seconds).
    """

    logger = logging.getLogger('sentinelsat.SentinelAPI')

    def __init__(self, user, password, api_url='https://scihub.copernicus.eu/apihub/',
                 show_progressbars=True, timeout=None):
        self.session = requests.Session()
        if user and password:
            self.session.auth = (user, password)
        self.api_url = api_url if api_url.endswith('/') else api_url + '/'
        self.page_size = 100
        self.user_agent = 'sentinelsat/' + sentinelsat_version
        self.session.headers['User-Agent'] = self.user_agent
        self.show_progressbars = show_progressbars
        self.timeout = timeout
        # For unit tests
        self._last_query = None
        self._last_response = None

    def query(self, area=None, date=None, raw=None, area_relation='Intersects',
              order_by=None, limit=None, offset=0, **keywords):
        """Query the OpenSearch API with the coordinates of an area, a date interval
        and any other search keywords accepted by the API.

        Parameters
        ----------
        area : str, optional
            The area of interest formatted as a Well-Known Text string.
        date : tuple of (str or datetime) or str, optional
            A time interval filter based on the Sensing Start Time of the products.
            Expects a tuple of (start, end), e.g. ("NOW-1DAY", "NOW").
            The timestamps can be either a Python datetime or a string in one of the
            following formats:

                - yyyyMMdd
                - yyyy-MM-ddThh:mm:ss.SSSZ (ISO-8601)
                - yyyy-MM-ddThh:mm:ssZ
                - NOW
                - NOW-<n>DAY(S) (or HOUR(S), MONTH(S), etc.)
                - NOW+<n>DAY(S)
                - yyyy-MM-ddThh:mm:ssZ-<n>DAY(S)
                - NOW/DAY (or HOUR, MONTH etc.) - rounds the value to the given unit

            Alternatively, an already fully formatted string such as "[NOW-1DAY TO NOW]" can be
            used as well.
        raw : str, optional
            Additional query text that will be appended to the query.
        area_relation : {'Intersects', 'Contains', 'IsWithin'}, optional
            What relation to use for testing the AOI. Case insensitive.

                - Intersects: true if the AOI and the footprint intersect (default)
                - Contains: true if the AOI is inside the footprint
                - IsWithin: true if the footprint is inside the AOI

        order_by: str, optional
            A comma-separated list of fields to order by (on server side).
            Prefix the field name by '+' or '-' to sort in ascending or descending order,
            respectively. Ascending order is used if prefix is omitted.
            Example: "cloudcoverpercentage, -beginposition".
        limit: int, optional
            Maximum number of products returned. Defaults to no limit.
        offset: int, optional
            The number of results to skip. Defaults to 0.
        **keywords
            Additional keywords can be used to specify other query parameters,
            e.g. `relativeorbitnumber=70`.
            See https://scihub.copernicus.eu/twiki/do/view/SciHubUserGuide/3FullTextSearch
            for a full list.


        Range values can be passed as two-element tuples, e.g. `cloudcoverpercentage=(0, 30)`.
        `None` can be used in range values for one-sided ranges, e.g. `orbitnumber=(16302, None)`.
        Ranges with no bounds (`orbitnumber=(None, None)`) will not be included in the query.

        The time interval formats accepted by the `date` parameter can also be used with
        any other parameters that expect time intervals (that is: 'beginposition', 'endposition',
        'date', 'creationdate', and 'ingestiondate').

        Returns
        -------
        dict[string, dict]
            Products returned by the query as a dictionary with the product ID as the key and
            the product's attributes (a dictionary) as the value.
        """
        query = _format_query(area, date, raw, area_relation, **keywords)

        self.logger.debug("Running query: order_by=%s, limit=%s, offset=%s, query=%s",
                          order_by, limit, offset, query)
        formatted_order_by = _format_order_by(order_by)
        response, count = self._load_query(query, formatted_order_by, limit, offset)
        self.logger.info("Found %s products", count)

        opensearch_dicts = _parse_opensearch_response(response)

        products = []
        for id in opensearch_dicts:
            products.append(Product(id, self.session, opensearch=opensearch_dicts[id], api_url=self.api_url, show_progressbars=self.show_progressbars))

        return products


    def query_raw(self, query, order_by=None, limit=None, offset=0):
        """
        Do a full-text query on the OpenSearch API using the format specified in
        https://scihub.copernicus.eu/twiki/do/view/SciHubUserGuide/3FullTextSearch

        DEPRECATED: use :meth:`query(raw=...) <.query>` instead. This method will be removed in the next major release.

        Parameters
        ----------
        query : str
            The query string.
        order_by: str, optional
            A comma-separated list of fields to order by (on server side).
            Prefix the field name by '+' or '-' to sort in ascending or descending order, respectively.
            Ascending order is used, if prefix is omitted.
            Example: "cloudcoverpercentage, -beginposition".
        limit: int, optional
            Maximum number of products returned. Defaults to no limit.
        offset: int, optional
            The number of results to skip. Defaults to 0.

        Returns
        -------
        dict[string, dict]
            Products returned by the query as a dictionary with the product ID as the key and
            the product's attributes (a dictionary) as the value.
        """
        warnings.warn(
            "query_raw() has been merged with query(). use query(raw=...) instead.",
            PendingDeprecationWarning
        )
        return self.query(raw=query, order_by=order_by, limit=limit, offset=offset)

    def count(self, area=None, date=None, raw=None, area_relation='Intersects', **keywords):
        """Get the number of products matching a query.

        Accepted parameters are identical to :meth:`SentinelAPI.query()`.

        This is a significantly more efficient alternative to doing `len(api.query())`,
        which can take minutes to run for queries matching thousands of products.

        Returns
        -------
        int
            The number of products matching a query.
        """
        for kw in ['order_by', 'limit', 'offset']:
            # Allow these function arguments to be included for compatibility with query(),
            # but ignore them.
            if kw in keywords:
                del keywords[kw]
        query = _format_query(area, date, raw, area_relation, **keywords)
        _, total_count = self._load_query(query, limit=0)
        return total_count

    def _load_query(self, query, order_by=None, limit=None, offset=0):
        products, count = self._load_subquery(query, order_by, limit, offset)

        # repeat query until all results have been loaded
        max_offset = count
        if limit is not None:
            max_offset = min(count, offset + limit)
        if max_offset > offset + self.page_size:
            progress = self._tqdm(desc="Querying products",
                                  initial=self.page_size,
                                  total=max_offset - offset,
                                  unit=' products')
            for new_offset in range(offset + self.page_size, max_offset, self.page_size):
                new_limit = limit
                if limit is not None:
                    new_limit = limit - new_offset + offset
                ret = self._load_subquery(query, order_by, new_limit, new_offset)[0]
                progress.update(len(ret))
                products += ret
            progress.close()

        return products, count

    def _load_subquery(self, query, order_by=None, limit=None, offset=0):
        # store last query (for testing)
        self._last_query = query
        self.logger.debug("Sub-query: offset=%s, limit=%s", offset, limit)

        # load query results
        url = self._format_url(order_by, limit, offset)
        response = self.session.post(url, {'q': query}, auth=self.session.auth,
                                     headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
                                     timeout=self.timeout)
        _check_scihub_response(response)

        # store last status code (for testing)
        self._last_response = response

        # parse response content
        try:
            json_feed = response.json()['feed']
            if json_feed['opensearch:totalResults'] is None:
                # We are using some unintended behavior of the server that a null is
                # returned as the total results value when the query string was incorrect.
                raise SentinelAPIError(
                    'Invalid query string. Check the parameters and format.', response)
            total_results = int(json_feed['opensearch:totalResults'])
        except (ValueError, KeyError):
            raise SentinelAPIError('API response not valid. JSON decoding failed.', response)

        products = json_feed.get('entry', [])
        # this verification is necessary because if the query returns only
        # one product, self.products will be a dict not a list
        if isinstance(products, dict):
            products = [products]

        return products, total_results

    def _format_url(self, order_by=None, limit=None, offset=0):
        if limit is None:
            limit = self.page_size
        limit = min(limit, self.page_size)
        url = 'search?format=json&rows={}'.format(limit)
        url += '&start={}'.format(offset)
        if order_by:
            url += '&orderby={}'.format(order_by)
        return urljoin(self.api_url, url)

    @staticmethod
    def to_geojson(products):
        """Return the products from a query response as a GeoJSON with the values in their
        appropriate Python types.
        """
        feature_list = []
        for i, product in enumerate(products):
            props = product.opensearch
            props = props.copy()
            props['id'] = product.id
            poly = geomet.wkt.loads(props['footprint'])
            del props['footprint']
            del props['gmlfootprint']
            # Fix "'datetime' is not JSON serializable"
            for k, v in props.items():
                if isinstance(v, (date, datetime)):
                    props[k] = v.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            feature_list.append(
                geojson.Feature(geometry=poly, id=i, properties=props)
            )
        return geojson.FeatureCollection(feature_list)

    @staticmethod
    def to_dataframe(products):
        """Return the products from a query response as a Pandas DataFrame
        with the values in their appropriate Python types.
        """
        try:
            import pandas as pd
        except ImportError:
            raise ImportError("to_dataframe requires the optional dependency Pandas.")

        productsDict = OrderedDict()
        for product in products:
            productsDict[product.id] = product.opensearch
        return pd.DataFrame.from_dict(productsDict, orient='index')

    @staticmethod
    def to_geodataframe(products):
        """Return the products from a query response as a GeoPandas GeoDataFrame
        with the values in their appropriate Python types.
        """
        try:
            import geopandas as gpd
            import shapely.wkt
        except ImportError:
            raise ImportError("to_geodataframe requires the optional dependencies GeoPandas and Shapely.")

        crs = {'init': 'epsg:4326'}  # WGS84
        if len(products) == 0:
            return gpd.GeoDataFrame(crs=crs)

        df = SentinelAPI.to_dataframe(products)
        geometry = [shapely.wkt.loads(fp) for fp in df['footprint']]
        # remove useless columns
        df.drop(['footprint', 'gmlfootprint'], axis=1, inplace=True)
        return gpd.GeoDataFrame(df, crs=crs, geometry=geometry)

    

    def download_all(self, products, directory_path='.', max_attempts=10, checksum=True, band_list=None):
        """Download a list of products.

        Takes a list of product IDs as input. This means that the return value of query() can be
        passed directly to this method.

        File names on the server are used for the downloaded files, e.g.
        "S1A_EW_GRDH_1SDH_20141003T003840_20141003T003920_002658_002F54_4DD1.zip".

        In case of interruptions or other exceptions, downloading will restart from where it left
        off. Downloading is attempted at most max_attempts times to avoid getting stuck with
        unrecoverable errors.

        Parameters
        ----------
        products : list
            List of product IDs
        band_list : list
            List of Sentinel 2 band in [B0, B1, ... B12, B8A, TCI]
        directory_path : string
            Directory where the downloaded files will be downloaded
        max_attempts : int, optional
            Number of allowed retries before giving up downloading a product. Defaults to 10.
        checksum : bool, optional
            If True, verify the downloaded files' integrity by checking its MD5 checksum.
            Throws InvalidChecksumError if the checksum does not match.
            Defaults to True.

        Raises
        ------
        Raises the most recent downloading exception if all downloads failed.

        Returns
        -------
        dict[string, dict]
            A dictionary containing the return value from download() for each successfully
            downloaded product.
        dict[string, dict]
            A dictionary containing the product information for products whose retrieval
            from the long term archive was successfully triggered.
        set[string]
            The list of products that failed to download.
        """
        product_ids = [product.id for product in products]
        self.logger.info("Will download %d products", len(product_ids))
        return_values = OrderedDict()
        last_exception = None
        for i, product in enumerate(products):
            product_id = product.id
            for attempt_num in range(max_attempts):
                try:
                    product_info = product.download(directory_path, checksum, band_list=band_list)
                    return_values[product_id] = product_info
                    break
                except (KeyboardInterrupt, SystemExit):
                    raise
                except InvalidChecksumError as e:
                    last_exception = e
                    self.logger.warning(
                        "Invalid checksum. The downloaded file for '%s' is corrupted.", product_id)
                except SentinelAPILTAError as e:
                    last_exception = e
                    self.logger.exception("There was an error retrieving %s from the LTA", product_id)
                    break
                except Exception as e:
                    last_exception = e
                    self.logger.exception("There was an error downloading %s", product_id)
            self.logger.info("%s/%s products downloaded", i + 1, len(product_ids))
        failed = set(products) - set(return_values)

        # split up sucessfully processed products into downloaded and only triggered retrieval from the LTA
        triggered = OrderedDict([(k, v) for k, v in return_values.items() if v['Online'] is False])
        downloaded = OrderedDict([(k, v) for k, v in return_values.items() if v['Online'] is True])


        if len(failed) == len(product_ids) and last_exception is not None:
            raise last_exception
        return downloaded, triggered, failed

    @staticmethod
    def get_products_size(products):
        """Return the total file size in GB of all products in the OpenSearch response."""
        size_total = 0
        for title, props in products.items():
            size_product = props["size"]
            size_value = float(size_product.split(" ")[0])
            size_unit = str(size_product.split(" ")[1])
            if size_unit == "MB":
                size_value /= 1024.
            if size_unit == "KB":
                size_value /= 1024. * 1024.
            size_total += size_value
        return round(size_total, 2)

    @staticmethod
    def check_query_length(query):
        """Determine whether a query to the OpenSearch API is too long.

        The length of a query string is limited to approximately 3938 characters but
        any special characters (that is, not alphanumeric or -_.*) will take up more space.

        Parameters
        ----------
        query : str
            The query string

        Returns
        -------
        float
            Ratio of the query length to the maximum length
        """
        # The server uses the Java's URLEncoder implementation internally, which we are replicating here
        effective_length = len(quote_plus(query, safe="-_.*").replace('~', '%7E'))
        return effective_length / 3938

    def _query_names(self, names):
        """Find products by their names, e.g.
        S1A_EW_GRDH_1SDH_20141003T003840_20141003T003920_002658_002F54_4DD1.

        Note that duplicates exist on server, so multiple products can be returned for each name.

        Parameters
        ----------
        names : list[string]
            List of product names.

        Returns
        -------
        dict[string, dict[str, dict]]
            A dictionary mapping each name to a dictionary which contains the products with
            that name (with ID as the key).
        """

        def chunks(l, n):
            """Yield successive n-sized chunks from l."""
            for i in range(0, len(l), n):
                yield l[i:i + n]

        products = {}
        # 40 names per query fits reasonably well inside the query limit
        for chunk in chunks(names, 40):
            query = " OR ".join(chunk)
            products.update(self.query(raw=query))

        # Group the products
        output = OrderedDict((name, dict()) for name in names)
        for id, metadata in products.items():
            name = metadata['identifier']
            output[name][id] = metadata

        return output

    def check_files(self, paths=None, ids=None, directory=None, delete=False):
        """Verify the integrity of product files on disk.

        Integrity is checked by comparing the size and checksum of the file with the respective
        values on the server.

        The input can be a list of products to check or a list of IDs and a directory.

        In cases where multiple products with different IDs exist on the server for given product
        name, the file is considered to be correct if any of them matches the file size and
        checksum. A warning is logged in such situations.

        The corrupt products' OData info is included in the return value to make it easier to
        re-download the products, if necessary.

        Parameters
        ----------
        paths : list[string]
            List of product file paths.
        ids : list[string]
            List of product IDs.
        directory : string
            Directory where the files are located, if checking based on product IDs.
        delete : bool
            Whether to delete corrupt products. Defaults to False.

        Returns
        -------
        dict[str, list[dict]]
            A dictionary listing the invalid or missing files. The dictionary maps the corrupt
            file paths to a list of OData dictionaries of matching products on the server (as
            returned by :meth:`SentinelAPI.get_product_odata()`).
        """
        if not ids and not paths:
            raise ValueError("Must provide either file paths or product IDs and a directory")
        if ids and not directory:
            raise ValueError("Directory value missing")
        paths = paths or []
        ids = ids or []

        def name_from_path(path):
            return splitext(basename(path))[0]

        # Get product IDs corresponding to the files on disk
        names = []
        if paths:
            names = list(map(name_from_path, paths))
            result = self._query_names(names)
            for product_dicts in result.values():
                ids += list(product_dicts)
        names_from_paths = set(names)
        ids = set(ids)

        # Collect the OData information for each product
        # Product name -> list of matching odata dicts
        product_infos = defaultdict(list)
        for id in ids:
            product = Product(id, self.session)
            odata = product.get_odata(id)
            name = odata['title']
            product_infos[name].append(odata)

            # Collect
            if name not in names_from_paths:
                paths.append(join(directory, name + '.zip'))

        # Now go over the list of products and check them
        corrupt = {}
        for path in paths:
            name = name_from_path(path)

            if len(product_infos[name]) > 1:
                self.logger.warning("{} matches multiple products on server".format(path))

            if not exists(path):
                # We will consider missing files as corrupt also
                self.logger.info("{} does not exist on disk".format(path))
                corrupt[path] = product_infos[name]
                continue

            is_fine = False
            for product_info in product_infos[name]:
                if (getsize(path) == product_info['size'] and
                        product._md5_compare(path, product_info['md5'])):
                    is_fine = True
                    break
            if not is_fine:
                self.logger.info("{} is corrupt".format(path))
                corrupt[path] = product_infos[name]
                if delete:
                    remove(path)

        return corrupt



def read_geojson(geojson_file):
    """Read a GeoJSON file into a GeoJSON object.
    """
    with open(geojson_file) as f:
        return geojson.load(f)


def geojson_to_wkt(geojson_obj, feature_number=0, decimals=4):
    """Convert a GeoJSON object to Well-Known Text. Intended for use with OpenSearch queries.

    In case of FeatureCollection, only one of the features is used (the first by default).
    3D points are converted to 2D.

    Parameters
    ----------
    geojson_obj : dict
        a GeoJSON object
    feature_number : int, optional
        Feature to extract polygon from (in case of MultiPolygon
        FeatureCollection), defaults to first Feature
    decimals : int, optional
        Number of decimal figures after point to round coordinate to. Defaults to 4 (about 10
        meters).

    Returns
    -------
    polygon coordinates
        string of comma separated coordinate tuples (lon, lat) to be used by SentinelAPI
    """
    if 'coordinates' in geojson_obj:
        geometry = geojson_obj
    elif 'geometry' in geojson_obj:
        geometry = geojson_obj['geometry']
    else:
        geometry = geojson_obj['features'][feature_number]['geometry']

    def ensure_2d(geometry):
        if isinstance(geometry[0], (list, tuple)):
            return list(map(ensure_2d, geometry))
        else:
            return geometry[:2]

    def check_bounds(geometry):
        if isinstance(geometry[0], (list, tuple)):
            return list(map(check_bounds, geometry))
        else:
            if geometry[0] > 180 or geometry[0] < -180:
                raise ValueError('Longitude is out of bounds, check your JSON format or data')
            if geometry[1] > 90 or geometry[1] < -90:
                raise ValueError('Latitude is out of bounds, check your JSON format or data')

    # Discard z-coordinate, if it exists
    geometry['coordinates'] = ensure_2d(geometry['coordinates'])
    check_bounds(geometry['coordinates'])

    wkt = geomet.wkt.dumps(geometry, decimals=decimals)
    # Strip unnecessary spaces
    wkt = re.sub(r'(?<!\d) ', '', wkt)
    return wkt


def format_query_date(in_date):
    """
    Format a date, datetime or a YYYYMMDD string input as YYYY-MM-DDThh:mm:ssZ
    or validate a date string as suitable for the full text search interface and return it.

    `None` will be converted to '\*', meaning an unlimited date bound in date ranges.

    Parameters
    ----------
    in_date : str or datetime or date or None
        Date to be formatted

    Returns
    -------
    str
        Formatted string

    Raises
    ------
    ValueError
        If the input date type is incorrect or passed date string is invalid
    """
    if in_date is None:
        return '*'
    if isinstance(in_date, (datetime, date)):
        return in_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    elif not isinstance(in_date, string_types):
        raise ValueError('Expected a string or a datetime object. Received {}.'.format(in_date))

    in_date = in_date.strip()
    if in_date == '*':
        # '*' can be used for one-sided range queries e.g. ingestiondate:[* TO NOW-1YEAR]
        return in_date

    # Reference: https://cwiki.apache.org/confluence/display/solr/Working+with+Dates

    # ISO-8601 date or NOW
    valid_date_pattern = r'^(?:\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z|NOW)'
    # date arithmetic suffix is allowed
    units = r'(?:YEAR|MONTH|DAY|HOUR|MINUTE|SECOND)'
    valid_date_pattern += r'(?:[-+]\d+{}S?)*'.format(units)
    # dates can be rounded to a unit of time
    # e.g. "NOW/DAY" for dates since 00:00 today
    valid_date_pattern += r'(?:/{}S?)*$'.format(units)
    in_date = in_date.strip()
    if re.match(valid_date_pattern, in_date):
        return in_date

    try:
        return datetime.strptime(in_date, '%Y%m%d').strftime('%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        raise ValueError('Unsupported date value {}'.format(in_date))


def _check_scihub_response(response, test_json=True):
    """Check that the response from server has status code 2xx and that the response is valid JSON.
    """
    # Prevent requests from needing to guess the encoding
    # SciHub appears to be using UTF-8 in all of their responses
    response.encoding = 'utf-8'
    try:
        response.raise_for_status()
        if test_json:
            response.json()
    except (requests.HTTPError, ValueError):
        msg = "Invalid API response."
        try:
            msg = response.headers['cause-message']
        except:
            try:
                msg = response.json()['error']['message']['value']
            except:
                if not response.text.strip().startswith('{'):
                    try:
                        h = html2text.HTML2Text()
                        h.ignore_images = True
                        h.ignore_anchors = True
                        msg = h.handle(response.text).strip()
                    except:
                        pass
        api_error = SentinelAPIError(msg, response)
        # Suppress "During handling of the above exception..." message
        # See PEP 409
        api_error.__cause__ = None
        raise api_error

