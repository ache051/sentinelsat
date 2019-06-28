# -*- coding: utf-8 -*-

import hashlib
import logging
import requests
import shutil
from contextlib import closing
from os import remove, mkdir
from os.path import basename, exists, getsize, join, splitext

from six.moves.urllib.parse import urljoin, quote_plus
from tqdm import tqdm

from .utils import _check_scihub_response, _parse_odata_timestamp, _parse_iso_date, _parse_gml_footprint, \
    _parse_manifest_xml, _make_opensearch_query, _format_query, _parse_opensearch_response, _parse_odata_response

from .error import InvalidChecksumError, SentinelAPILTAError

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

    logger = logging.getLogger('sentinelsat.product')

    def __init__(self, id, session, opensearch=opensearch, api_url='https://scihub.copernicus.eu/apihub/', show_progressbars=True, timeout=None):
        self.id = id
        if not isinstance(session, requests.Session):
            raise ValueError("Product must be created with a requests.Session object") 
        self.__session = session
        self.__api_url = api_url
        self.__timeout = timeout
        self.__show_progressbars = show_progressbars
        self.opensearch = opensearch

        if not self.opensearch:
            self.opensearch = self._get_opensearch()


    def __str__(self):
        return str(self.opensearch)

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
        url = urljoin(self.__api_url, u"odata/v1/Products('{}')?$format=json".format(self.id))
        if full:
            url += '&$expand=Attributes'
        response = self.__session.get(url, timeout=self.__timeout)
        _check_scihub_response(response)
        return _parse_odata_response(response.json()['d'])

    def download(self, directory_path='.', checksum=True, band_list=None):
        """Download a product.

        Uses the filename on the server for the downloaded file, e.g.
        "S1A_EW_GRDH_1SDH_20141003T003840_20141003T003920_002658_002F54_4DD1.zip".

        Incomplete downloads are continued and complete files are skipped.

        Parameters
        ----------
        id : string
            UUID of the product, e.g. 'a8dd0cfd-613e-45ce-868c-d79177b916ed'
        band_list : list
            List of Sentinel 2 band in [B0, B1, ... B12, B8A, TCI]
        directory_path : string, optional
            Where the file will be downloaded
        checksum : bool, optional
            If True, verify the downloaded file's integrity by checking its MD5 checksum.
            Throws InvalidChecksumError if the checksum does not match.
            Defaults to True.

        Returns
        -------
        product_info : dict
            Dictionary containing the product's info from get_product_info() as well as
            the path on disk.

        Raises
        ------
        InvalidChecksumError
            If the MD5 checksum does not match the checksum on the server.
        """
        product_info = self.get_odata(id)
        path = join(directory_path, product_info['title'] + '.zip')
        product_info['path'] = path
        product_info['downloaded_bytes'] = 0

        # An incomplete download triggers the retrieval from the LTA if the product is not online
        if not product_info['Online']:
            self.logger.warning(
                'Product %s is not online. Triggering retrieval from long term archive.',
                product_info['id'])
            self._trigger_offline_retrieval(product_info['url'])
            return product_info


        if band_list:
            if str.startswith(product_info['title'], 'S2'):
                band_dict = {
                    'B01': 'IMG_DATA_Band_60m_1_Tile1_Data',
                    'B02': 'IMG_DATA_Band_10m_1_Tile1_Data',
                    'B03': 'IMG_DATA_Band_10m_2_Tile1_Data',
                    'B04': 'IMG_DATA_Band_10m_3_Tile1_Data',
                    'B05': 'IMG_DATA_Band_20m_1_Tile1_Data',
                    'B06': 'IMG_DATA_Band_20m_2_Tile1_Data',
                    'B07': 'IMG_DATA_Band_20m_3_Tile1_Data',
                    'B08': 'IMG_DATA_Band_10m_4_Tile1_Data',
                    'B09': 'IMG_DATA_Band_60m_2_Tile1_Data',
                    'B10': 'IMG_DATA_Band_60m_3_Tile1_Data',
                    'B11': 'IMG_DATA_Band_20m_5_Tile1_Data',
                    'B12': 'IMG_DATA_Band_20m_6_Tile1_Data',
                    'B8A': 'IMG_DATA_Band_20m_4_Tile1_Data',
                    'TCI': 'IMG_DATA_Band_TCI_Tile1_Data'
                }
                manifest = self.get_manifest()
                files_info = []
                for band in band_list:
                    if band not in band_dict:
                        self.logger.error('Band %s does not exists in Sentinel-2 product.', band)
                    band_id = band_dict[band]
                    file_info = [file_info for file_info in manifest if file_info['id'] == band_id][0]
                    file_info['url'] = '/'.join(product_info['url'].split('/')[:-1]) + "/Nodes('{}.SAFE')/".format(product_info['title'])
                    file_info['url'] += '/'.join(["Nodes('{}')".format(token) for token in file_info['href'].split('/')[1:]]) + '/$value'

                    if not exists(join(directory_path, product_info['title'])):
                        mkdir(join(directory_path, product_info['title']))
                    path = join(directory_path, product_info['title'], file_info['href'].split('/')[-1])

                    self.logger.info('Downloading band %s of %s to %s', band_id, id, path)
                    file_info = self._download_file_with_resume(file_info, path)
                    files_info.append(file_info)
                product_info['bands'] = files_info
                return product_info
            else:
                self.logger.error('band_list argument (%s) only compatible with Sentinel-2 product.', band_list)
        else:
            self.logger.info('Downloading %s to %s', id, path)
            return self._download_file_with_resume(product_info, path, checksum=checksum)

    def _download_file_with_resume(self, file_info, path, checksum=False):

        if exists(path):
            # We assume that the product has been downloaded and is complete
            return file_info

        # Use a temporary file for downloading
        temp_path = path + '.incomplete'

        skip_download = False
        if exists(temp_path):
            if getsize(temp_path) > file_info['size']:
                self.logger.warning(
                    "Existing incomplete file %s is larger than the expected final size"
                    " (%s vs %s bytes). Deleting it.",
                    str(temp_path), getsize(temp_path), file_info['size'])
                remove(temp_path)
            elif getsize(temp_path) == file_info['size']:
                if self._md5_compare(temp_path, file_info['md5']):
                    skip_download = True
                else:
                    # Log a warning since this should never happen
                    self.logger.warning(
                        "Existing incomplete file %s appears to be fully downloaded but "
                        "its checksum is incorrect. Deleting it.",
                        str(temp_path))
                    remove(temp_path)
            else:
                # continue downloading
                self.logger.info(
                    "Download will resume from existing incomplete file %s.", temp_path)
                pass

        if not skip_download:
            # Store the number of downloaded bytes for unit tests
            file_info['downloaded_bytes'] = self._download(
                file_info['url'], temp_path, self.__session, file_info['size'])

        # Check integrity with MD5 checksum
        if checksum is True:
            if not self._md5_compare(temp_path, file_info['md5']):
                remove(temp_path)
                raise InvalidChecksumError('File corrupt: checksums do not match')

        # Download successful, rename the temporary file to its proper name
        shutil.move(temp_path, path)

        return file_info

    def _md5_compare(self, file_path, checksum, block_size=2 ** 13):
        """Compare a given MD5 checksum with one calculated from a file."""
        with closing(self._tqdm(desc="MD5 checksumming", total=getsize(file_path), unit="B",
                                unit_scale=True)) as progress:
            md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                while True:
                    block_data = f.read(block_size)
                    if not block_data:
                        break
                    md5.update(block_data)
                    progress.update(len(block_data))
            return md5.hexdigest().lower() == checksum.lower()


    def _download(self, url, path, session, file_size):
        headers = {}
        continuing = exists(path)
        if continuing:
            already_downloaded_bytes = getsize(path)
            headers = {'Range': 'bytes={}-'.format(already_downloaded_bytes)}
        else:
            already_downloaded_bytes = 0
        downloaded_bytes = 0
        with closing(session.get(url, stream=True, auth=session.auth,
                                 headers=headers, timeout=self.__timeout)) as r, \
                closing(self._tqdm(desc="Downloading", total=file_size, unit="B",
                                   unit_scale=True, initial=already_downloaded_bytes)) as progress:
            _check_scihub_response(r, test_json=False)
            chunk_size = 2 ** 20  # download in 1 MB chunks
            mode = 'ab' if continuing else 'wb'
            with open(path, mode) as f:
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)
                        progress.update(len(chunk))
                        downloaded_bytes += len(chunk)
            # Return the number of bytes downloaded
            return downloaded_bytes

    def _tqdm(self, **kwargs):
        """tqdm progressbar wrapper. May be overridden to customize progressbar behavior"""
        kwargs.update({'disable': not self.__show_progressbars})
        return tqdm(**kwargs)


    def _trigger_offline_retrieval(self, url):
        """ Triggers retrieval of an offline product

        Trying to download an offline product triggers its retrieval from the long term archive.
        The returned HTTP status code conveys whether this was successful.

        Parameters
        ----------
        url : string
            URL for downloading the product

        Notes
        -----
        https://scihub.copernicus.eu/userguide/LongTermArchive

        """
        with self.session.get(url, auth=self.session.auth, timeout=self.timeout) as r:
            # check https://scihub.copernicus.eu/userguide/LongTermArchive#HTTP_Status_codes
            if r.status_code == 202:
                self.logger.info("Accepted for retrieval")
            elif r.status_code == 503:
                self.logger.error("Request not accepted")
                raise SentinelAPILTAError('Request for retrieval from LTA not accepted', r)
            elif r.status_code == 403:
                self.logger.error("Requests exceed user quota")
                raise SentinelAPILTAError('Requests for retrieval from LTA exceed user quota', r)
            elif r.status_code == 500:
                # should not happen
                self.logger.error("Trying to download an offline product")
                raise SentinelAPILTAError('Trying to download an offline product', r)
            return r.status_code
    
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
        odata = self.get_odata()
        name = "{}.SAFE".format(odata['title'])
        
        # get opensearch metadata with a query request with filename keyword
        query = _format_query(filename=name)
        response, _ = _make_opensearch_query(self.__session, self.__api_url, query, limit=1)
        opensearch_dict = _parse_opensearch_response(response)

        return opensearch_dict[self.id]

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
        url = urljoin(self.__api_url,
            u"odata/v1/Products('{}')/Nodes('{}.SAFE')/Nodes('manifest.safe')/$value"
            .format(self.id, self.opensearch['title']))
        response = self.__session.get(url, timeout=self.__timeout)
        _check_scihub_response(response, test_json=False)
        values = _parse_manifest_xml(response.content)
        return values

    def get_file_list(self):

        return []

    def get_file_content(self):

        return ""

    def download_file(self):
        pass



