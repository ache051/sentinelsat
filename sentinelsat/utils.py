# -*- coding: utf-8 -*

import xml.etree.ElementTree as ET
from collections import OrderedDict, defaultdict
from datetime import date, datetime, timedelta
import requests
import re

from six import string_types
from six.moves.urllib.parse import urljoin

from .error import SentinelAPIError



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
        #api_error = Exception(msg)
        # Suppress "During handling of the above exception..." message
        # See PEP 409
        api_error.__cause__ = None
        raise api_error


def _parse_iso_date(content):
    if '.' in content:
        return datetime.strptime(content, '%Y-%m-%dT%H:%M:%S.%fZ')
    else:
        return datetime.strptime(content, '%Y-%m-%dT%H:%M:%SZ')


def _parse_odata_timestamp(in_date):
    """Convert the timestamp received from OData JSON API to a datetime object.
    """
    timestamp = int(in_date.replace('/Date(', '').replace(')/', ''))
    seconds = timestamp // 1000
    ms = timestamp % 1000
    return datetime.utcfromtimestamp(seconds) + timedelta(milliseconds=ms)


def _parse_gml_footprint(geometry_str):
    geometry_xml = ET.fromstring(geometry_str)
    poly_coords_str = geometry_xml \
        .find('{http://www.opengis.net/gml}outerBoundaryIs') \
        .find('{http://www.opengis.net/gml}LinearRing') \
        .findtext('{http://www.opengis.net/gml}coordinates')
    poly_coords = (coord.split(",")[::-1] for coord in poly_coords_str.split(" "))
    coord_string = ",".join(" ".join(coord) for coord in poly_coords)
    return "POLYGON(({}))".format(coord_string)



def _parse_opensearch_response(products):
    """Convert a query response to a dictionary.

    The resulting dictionary structure is {<product id>: {<property>: <value>}}.
    The property values are converted to their respective Python types unless `parse_values`
    is set to `False`.
    """

    converters = {'date': _parse_iso_date, 'int': int, 'long': int, 'float': float, 'double': float}
    # Keep the string type by default
    default_converter = lambda x: x

    output = OrderedDict()
    for prod in products:
        product_dict = {}
        prod_id = prod['id']
        output[prod_id] = product_dict
        for key in prod:
            if key == 'id':
                continue
            if isinstance(prod[key], string_types):
                product_dict[key] = prod[key]
            else:
                properties = prod[key]
                if isinstance(properties, dict):
                    properties = [properties]
                if key == 'link':
                    for p in properties:
                        name = 'link'
                        if 'rel' in p:
                            name = 'link_' + p['rel']
                        product_dict[name] = p['href']
                else:
                    f = converters.get(key, default_converter)
                    for p in properties:
                        try:
                            product_dict[p['name']] = f(p['content'])
                        except KeyError:
                            # Sentinel-3 has one element 'arr'
                            # which violates the name:content convention
                            product_dict[p['name']] = f(p['str'])
    return output


def _parse_odata_response(product):
    output = {
        'id': product['Id'],
        'title': product['Name'],
        'size': int(product['ContentLength']),
        product['Checksum']['Algorithm'].lower(): product['Checksum']['Value'],
        'date': _parse_odata_timestamp(product['ContentDate']['Start']),
        'footprint': _parse_gml_footprint(product["ContentGeometry"]),
        'url': product['__metadata']['media_src'],
        'Online': product.get('Online', True),
        'Creation Date': _parse_odata_timestamp(product['CreationDate']),
        'Ingestion Date': _parse_odata_timestamp(product['IngestionDate']),
    }
    # Parse the extended metadata, if provided
    converters = [int, float, _parse_iso_date]
    for attr in product['Attributes'].get('results', []):
        value = attr['Value']
        for f in converters:
            try:
                value = f(attr['Value'])
                break
            except ValueError:
                pass
        output[attr['Name']] = value
    return output


def _parse_manifest_xml(xml):
    outputs = []
    root = ET.fromstring(xml)
    for item in root.findall("./dataObjectSection/dataObject"):
        output = {
            'id': item.get('ID'),
            'mimetype': item.find('./byteStream').get('mimeType'),
            'size': int(item.find('./byteStream').get('size')),
            'href': item.find('./byteStream/fileLocation').get('href'),
            'md5sum': item.find('./byteStream/checksum').text
        }
        outputs.append(output)

    return outputs



def _format_url(api_url, order_by=None, limit=None, offset=0):
    url = 'search?format=json&rows={}'.format(limit)
    url += '&start={}'.format(offset)
    if order_by:
        url += '&orderby={}'.format(order_by)
    return urljoin(api_url, url)

def _make_opensearch_query(session, api_url, query, order_by=None, limit=None, offset=0, timeout=None):

    # load query results
    url = _format_url(api_url, order_by, limit, offset)
    response = session.post(url, {'q': query}, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
                                    timeout=timeout)
    _check_scihub_response(response)

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


def _format_query(area=None, date=None, raw=None, area_relation='Intersects',
                    **keywords):
    """Create a OpenSearch API query string.
    """
    if area_relation.lower() not in {"intersects", "contains", "iswithin"}:
        raise ValueError("Incorrect AOI relation provided ({})".format(area_relation))

    # Check for duplicate keywords
    kw_lower = set(x.lower() for x in keywords)
    if (len(kw_lower) != len(keywords) or
            (date is not None and 'beginposition' in kw_lower) or
            (area is not None and 'footprint' in kw_lower)):
        raise ValueError("Query contains duplicate keywords. Note that query keywords are case-insensitive.")

    query_parts = []

    if date is not None:
        keywords['beginPosition'] = date

    for attr, value in sorted(keywords.items()):
        # Escape spaces, where appropriate
        if isinstance(value, string_types):
            value = value.strip()
            if not any(value.startswith(s[0]) and value.endswith(s[1]) for s in ['[]', '{}', '//', '()']):
                value = re.sub(r'\s', r'\ ', value, re.M)

        # Handle date keywords
        # Keywords from https://github.com/SentinelDataHub/DataHubSystem/search?q=text/date+iso8601
        date_attrs = ['beginposition', 'endposition', 'date', 'creationdate', 'ingestiondate']
        if attr.lower() in date_attrs:
            # Automatically format date-type attributes
            if isinstance(value, string_types) and ' TO ' in value:
                # This is a string already formatted as a date interval,
                # e.g. '[NOW-1DAY TO NOW]'
                pass
            elif not isinstance(value, string_types) and len(value) == 2:
                value = (format_query_date(value[0]), format_query_date(value[1]))
            else:
                raise ValueError("Date-type query parameter '{}' expects a two-element tuple "
                                    "of str or datetime objects. Received {}".format(attr, value))

        # Handle ranged values
        if isinstance(value, (list, tuple)):
            # Handle value ranges
            if len(value) == 2:
                # Allow None to be used as a unlimited bound
                value = ['*' if x is None else x for x in value]
                if all(x == '*' for x in value):
                    continue
                value = '[{} TO {}]'.format(*value)
            else:
                raise ValueError("Invalid number of elements in list. Expected 2, received "
                                    "{}".format(len(value)))

        query_parts.append('{}:{}'.format(attr, value))

    if raw:
        query_parts.append(raw)

    if area is not None:
        query_parts.append('footprint:"{}({})"'.format(area_relation, area))

    return ' '.join(query_parts)


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
