# -*- coding: utf-8 -*-

import requests
from six.moves.urllib.parse import urljoin, quote_plus

from .utils import _check_scihub_response, _parse_odata_timestamp, _parse_iso_date, _parse_gml_footprint, \
    _parse_manifest_xml, _make_opensearch_query, _format_query, _parse_opensearch_response, _parse_odata_response

class Product:
    """Product class for Copernicus Open Access Hub API

    Parameters
    ----------
    id : string
        The UUID of the product
    session: requests.Session
        A requests.Session object containing authentication info for scihub API
    api_url : string, optional
        URL of the DataHub
        defaults to 'https://scihub.copernicus.eu/apihub'
    timeout : float or tuple, optional
        How long to wait for DataHub response (in seconds).
        Tuple (connect, read) allowed.

    Attributes
    ----------
    session : requests.Session
        Session to connect to DataHub
    api_url : str
        URL to the DataHub
    timeout : float or tuple
        How long to wait for DataHub response (in seconds).
    id : string
        The UUID of the product
    name: str
        The name of the product. See:
        [Sentinel-1 naming convention] https://sentinel.esa.int/web/sentinel/user-guides/sentinel-1-sar/naming-conventions
        [Sentinel-2 naming convention] https://sentinel.esa.int/web/sentinel/user-guides/sentinel-2-msi/naming-convention
        [Sentinel-3 OLCI naming convention] https://sentinel.esa.int/web/sentinel/user-guides/sentinel-3-olci/naming-convention
        [Sentinel-3 SLSTR naming convention] https://sentinel.esa.int/web/sentinel/user-guides/sentinel-3-slstr/naming-convention
        [Sentinel-3 SRAL naming convention] https://sentinel.esa.int/web/sentinel/user-guides/sentinel-3-altimetry/naming-conventions
        [Sentinel-3 Synergy naming convention] https://sentinel.esa.int/web/sentinel/user-guides/sentinel-3-synergy/naming-conventions
        [Sentinel-5P naming convention] https://sentinels.copernicus.eu/documents/247904/2506504/FFS-Tailoring-Sentinel-5P.pdf
    opensearch: dict[str, Any]
        OpenSearch result for product
        see _get_opensearch
    """

    def __init__(self, id, session, api_url='https://scihub.copernicus.eu/apihub/', timeout=None, opensearch={}):
        self.id = id
        if not isinstance(session, requests.Session):
            raise ValueError("Product must be created with a requests.Session object") 
        self.session = session
        self.api_url = api_url
        self.timeout = timeout
        if not opensearch:
            opensearch = self._get_opensearch()
        self.opensearch = opensearch
        self.name = "{}.SAFE".format(self.opensearch['title'])

    def get_odata(self, full=False):
        """Access OData API to get info about a product.

        Returns a dict containing the id, title, size, md5sum, date, footprint and download url
        of the product. The date field corresponds to the Start ContentDate value.

        If `full` is set to True, then the full, detailed metadata of the product is returned
        in addition to the above.

        Parameters
        ----------
        full : bool
            Whether to get the full metadata for the Product. False by default.

        Returns
        -------
        dict[str, Any]
            A dictionary with an item for each metadata attribute

        Notes
        -----
        For a full list of mappings between the OpenSearch (Solr) and OData attribute names
        see the following definition files:
        https://github.com/SentinelDataHub/DataHubSystem/blob/master/addon/sentinel-1/src/main/resources/META-INF/sentinel-1.owl
        https://github.com/SentinelDataHub/DataHubSystem/blob/master/addon/sentinel-2/src/main/resources/META-INF/sentinel-2.owl
        https://github.com/SentinelDataHub/DataHubSystem/blob/master/addon/sentinel-3/src/main/resources/META-INF/sentinel-3.owl
        """
        url = urljoin(self.api_url, u"odata/v1/Products('{}')?$format=json".format(self.id))
        if full:
            url += '&$expand=Attributes'
        response = self.session.get(url, timeout=self.timeout)
        _check_scihub_response(response)
        return _parse_odata_response(response.json()['d'])


    def _get_opensearch(self):
        """Access OpenSearch API to get info about a product.

        Returns a dict containing the id, title, size, md5sum, date, footprint and download url
        of the product. The date field corresponds to the Start ContentDate value.

        Returns
        -------
        dict[str, Any]
            A dictionary with an item for each metadata attribute

        Notes
        -----
        For a full list of mappings between the OpenSearch (Solr) and OData attribute names
        see the following definition files:
        https://github.com/SentinelDataHub/DataHubSystem/blob/master/addon/sentinel-1/src/main/resources/META-INF/sentinel-1.owl
        https://github.com/SentinelDataHub/DataHubSystem/blob/master/addon/sentinel-2/src/main/resources/META-INF/sentinel-2.owl
        https://github.com/SentinelDataHub/DataHubSystem/blob/master/addon/sentinel-3/src/main/resources/META-INF/sentinel-3.owl
        """
        if not self.name:
            self.odata = self.get_odata()
            name = "{}.SAFE".format(self.odata['title'])
        
        # get opensearch metadata with a query request with filename keyword
        query = _format_query(filename=name)
        response, _ = _make_opensearch_query(self.session, self.api_url, query, limit=1)
        opensearch_dict = _parse_opensearch_response(response)

        return opensearch_dict[self.id]           

    def download(self):
        pass

    
    def get_manifest(self):
        """Access manifest file for product.

        Returns an array of dict for each file containing id, mimeType, size, href, md5sum
        extracted from <dataObjectSection> of xml file.

        Parameters
        ----------
        id : string
            The UUID of the product to query
        product_name : string
            The name of product

        Returns
        -------
        [dict[str, Any]]
            An array of dictionaries for each file with an item for each metadata attribute

        Notes
        -----
        Manifest is presented as an XML file here is an extract of dataObjectSection:
        <xfdu:XFDU xmlns:xfdu="urn:ccsds:schema:xfdu:1" xmlns:gml="http://www.opengis.net/gml" xmlns:safe="http://www.esa.int/safe/sentinel/1.1" version="esa/safe/sentinel/1.1/sentinel-2/msi/archive_l1c_user_product">
            ...
            <dataObjectSection>
                <dataObject ID="S2_Level-1C_Product_Metadata">
                    <byteStream mimeType="text/xml" size="44191">
                        <fileLocation locatorType="URL" href="./MTD_MSIL1C.xml" />
                        <checksum checksumName="MD5">fa7937f8b6bb880d6617cc991de5e065</checksum>
                    </byteStream>
                </dataObject>
                ...
            </dataObjectSection>
        </xfdu:XFDU>
        """
        if self.opensearch['platformname'] not in ['Sentinel-1', 'Sentinel-2']:
            raise ValueError('Manifest only available for Sentinel-1 and Sentinel-2 products.')
        url = urljoin(self.api_url,
            u"odata/v1/Products('{}')/Nodes('{}')/Nodes('manifest.safe')/$value"
            .format(self.id, self.name))
        response = self.session.get(url, timeout=self.timeout)
        _check_scihub_response(response, test_json=False)
        values = _parse_manifest_xml(response.content)
        return values

    def get_file_list(self):

        return []

    def get_file_content(self):

        return ""

    def download_file(self):
        pass



