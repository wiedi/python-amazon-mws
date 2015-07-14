#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Basic interface to Amazon MWS
# Based on http://code.google.com/p/amazon-mws-python
# #-G: making updates to attempt to hack this project into a
#      workable state on Python 3 and Django 1.7
#      My changes can be found by searching for '#-G'
#

import urllib
import hashlib
import hmac
import base64
from . import utils #-G: added `from . ` in front
import re
try:
    from xml.etree.ElementTree import ParseError as XMLError
except ImportError:
    from xml.parsers.expat import ExpatError as XMLError
from datetime import datetime

from requests import request
from requests.exceptions import HTTPError


__all__ = [
    'Feeds',
    'Inventory',
    'MWSError',
    'Reports',
    'Orders',
    'Products',
    'Recommendations',
    'Sellers',
]

# List of MWS endpoints and MarketplaceId values:
# http://docs.developer.amazonservices.com/en_US/dev_guide/DG_Endpoints.html
MARKETPLACES = {
    "CA" : "https://mws.amazonservices.ca", #A2EUQ1WTGCTBG2
    "US" : "https://mws.amazonservices.com", #ATVPDKIKX0DER",
    "DE" : "https://mws-eu.amazonservices.com", #A1PA6795UKMFR9
    "ES" : "https://mws-eu.amazonservices.com", #A1RKKUPIHCS9HS
    "FR" : "https://mws-eu.amazonservices.com", #A13V1IB3VIYZZH
    "IN" : "https://mws.amazonservices.in", #A21TJRUUN4KGV
    "IT" : "https://mws-eu.amazonservices.com", #APJ6JRA9NG5V4
    "UK" : "https://mws-eu.amazonservices.com", #A1F83G8C2ARO7P
    "JP" : "https://mws.amazonservices.jp", #A1VC38T7YXB528
    "CN" : "https://mws.amazonservices.com.cn", #AAHKV2X7AFYLW
}


class MWSError(Exception):
    """ Main MWS Exception class """
    # Allows quick access to the response object.
    # Do not rely on this attribute, always check if its not None.
    response = None


def calc_md5(string):
    """Calculates the MD5 encryption for the given string
    """
    md = hashlib.md5()
    md.update(string)
    #-G: per commit by bloodywing, making the strip `b'\n'`
    return base64.encodestring(md.digest()).strip(b'\n')


def remove_empty(d):
    """ Helper function that removes all keys from a dictionary (d),
        that have an empty value.
    """
    # for key in d.keys():
        # if not d[key]:
            # del d[key]
    
    #-G: The above method cannot be used: throws an error about the size
    #    of the dict changing during iteration.
    #    Instead of deleting bad keys from the original,
    #    return a new dict comprehension for truthy values
    return {k: v for k, v in d.items() if v}


def remove_namespace(xml):
    regex = re.compile(' xmlns(:ns2)?="[^"]+"|(ns2:)|(xml:)')
    try:
        out = regex.sub('', xml)
    except TypeError:
        #-G: In Py3 version, would get this saying
        # "can't use a string pattern on a bytes-like object"
        # decoding the output first.
        out = regex.sub('', xml.decode('utf-8'))
    return out


class DictWrapper(object):
    def __init__(self, xml, rootkey=None):
        self.original = xml
        self._rootkey = rootkey
        self._mydict = utils.xml2dict().fromstring(remove_namespace(xml))
        #-G: .keys() generates a dict_keys object,
        #    which cannot be indexed in Py3.
        #    Converting to list first.
        self._response_dict = self._mydict.get(
            list(self._mydict.keys())[0],
            self._mydict
        )

    @property
    def parsed(self):
        if self._rootkey:
            return self._response_dict.get(self._rootkey)
        else:
            return self._response_dict
    
    @property
    def metadata(self):
        """ Makes response metadata available, which otherwise
            cannot be seen in `.parsed`.
            
            Typical use: '.metadata.RequestId'
            #-G
        """
        return self._response_dict.get('ResponseMetadata')


class DataWrapper(object):
    """ Text wrapper in charge of validating the hash sent by Amazon. """
    def __init__(self, data, header):
        self.original = data
        if 'content-md5' in header:
            hash_ = calc_md5(self.original)
            if header['content-md5'] != hash_:
                raise MWSError("Wrong Contentlength, maybe amazon error...")

    @property
    def parsed(self):
        return self.original


class MWS(object):
    """ Base Amazon API class """

    # This is used to post/get to the different uris used by amazon per api
    # ie. /Orders/2011-01-01
    # All subclasses must define their own URI only if needed
    URI = "/"

    # The API version varies in most amazon APIs
    VERSION = "2009-01-01"

    # There seem to be some xml namespace issues. therefore every api subclass
    # is recommended to define its namespace, so that it can be referenced
    # like so AmazonAPISubclass.NS.
    # For more information see http://stackoverflow.com/a/8719461/389453
    NS = ''
    
    # In here we name each of the operations available to the subclass
    # that have 'ByNextToken' operations associated with them.
    # If the Operation is not listed here, self.action_by_next_token
    # will raise an error.
    NEXT_TOKEN_OPERATIONS = []

    # Some APIs are available only to either a "Merchant" or "Seller"
    # the type of account needs to be sent in every call to the amazon MWS.
    # This constant defines the exact name of the parameter Amazon expects
    # for the specific API being used.
    # All subclasses need to define this if they require another account type
    # like "Merchant" in which case you define it like so.
    # ACCOUNT_TYPE = "Merchant"
    # Which is the name of the parameter for that specific account type.
    ACCOUNT_TYPE = "SellerId"

    def __init__(self, access_key, secret_key, account_id,
                 region='US', domain='', uri="", version="", auth_token=""):
        self.access_key = access_key
        self.secret_key = secret_key
        self.account_id = account_id
        self.auth_token = auth_token
        self.version = version or self.VERSION
        self.uri = uri or self.URI

        if domain:
            self.domain = domain
        elif region in MARKETPLACES:
            self.domain = MARKETPLACES[region]
        else:
            error_msg = (
                "Incorrect region supplied ('{region}'). Must be one "
                "of the following: {marketplaces}"
            ).format(
                marketplaces=', '.join(MARKETPLACES.keys()),
                region=region,
            )
            raise MWSError(error_msg)

    def make_request(self, extra_data, method="GET", **kwargs):
        """ Make request to Amazon MWS API with these parameters """

        # Remove all keys with an empty value because
        # Amazon's MWS does not allow such a thing.
        extra_data = remove_empty(extra_data)
        #-G: storing timestamp for use later
        now = self.get_timestamp()

        params = {
            'AWSAccessKeyId': self.access_key,
            self.ACCOUNT_TYPE: self.account_id,
            'SignatureVersion': '2',
            'Timestamp': now, #-G: calling that stored timestamp
            'Version': self.version,
            'SignatureMethod': 'HmacSHA256',
        }
        if self.auth_token:
            params['MWSAuthToken'] = self.auth_token
        params.update(extra_data)
        
        request_description = '&'.join([
            '{key}={value}'.format(
                key=k,
                value=urllib.parse.quote(params[k], safe='-_.~'),
            ) for k in sorted(params)
        ])
        signature = self.calc_signature(method, request_description)
        url = '{domain}{uri}?{description}&Signature={signature}'.format(
            domain=self.domain,
            uri=self.uri,
            description=request_description,
            signature=urllib.parse.quote(signature),
        )
        headers = {'User-Agent': 'python-amazon-mws/0.0.1 (Language=Python)'}
        headers.update(kwargs.get('extra_headers', {}))

        try:
            # Some might wonder as to why I don't pass the params dict
            # as the params argument to request. My answer is, here I have
            # to get the url parsed string of params in order to sign it, so
            # if I pass the params dict as params to request, request will
            # repeat that step because it will need to convert the dict to
            # a url parsed string, so why do it twice if I can just pass
            # the full url :).
            response = request(
                method,
                url,
                data=kwargs.get('body', ''),
                headers=headers,
            )
            response.raise_for_status()
            # When retrieving data from the response object,
            # be aware that response.content returns the content in bytes
            # while response.text calls response.content and
            # converts it to unicode.
            data = response.content

            # I do not check the headers to decide which content structure
            # to server simply because sometimes Amazon's MWS API returns
            # XML error responses with "text/plain" as the Content-Type.
            try:
                parsed_response = DictWrapper(
                    data, extra_data.get("Action") + "Result"
                )
            except XMLError:
                parsed_response = DataWrapper(data, response.headers)

        except HTTPError as e:
            error = MWSError(str(e))
            error.response = e.response
            raise error

        # Store the response object in the parsed_response for quick access
        parsed_response.response = response
        # MWS recommends saving timestamp, so we make it available.
        parsed_response.timestamp = now
        return parsed_response

    def get_service_status(self):
        """ Returns a GREEN, GREEN_I, YELLOW or RED status,
            depending on the status/availability of the API
            it's being called from.
        """
        return self.make_request(extra_data=dict(Action='GetServiceStatus'))
    
    def action_by_next_token(self, action, next_token):
        """ Run a '...ByNextToken' action for the given action.
            If the action is not listed in self.NEXT_TOKEN_OPERATIONS,
            MWSError will be raised.
            Action is expected NOT to include 'ByNextToken'
            at the end of its name for this call: function will add that
            by itself.
        """
        if action not in self.NEXT_TOKEN_OPERATIONS:
            raise MWSError((
                "{} action not listed in this API's NEXT_TOKEN_OPERATIONS. "
                "Please refer to documentation."
            ).format(action))
        
        action = '{}ByNextToken'.format(action)
        
        data = dict(
            Action=action,
            NextToken=next_token
        )
        return self.make_request(data, method="POST")

    def calc_signature(self, method, request_description):
        """ Calculate MWS signature to interface with Amazon """
        sig_data = '\n'.join([
            method,
            self.domain.replace('https://', '').lower(),
            self.uri,
            request_description
        ])
        #-G: `hmac` in Py3 takes bytes or a bytesarray, not a str.
        #    Transforming `self.secret_key` and `sig_data` into bytearrays
        #    by adding .encode('utf-8') to the end of each (testing...)
        return base64.b64encode(
            hmac.new(str(self.secret_key).encode('utf-8'),
            sig_data.encode('utf-8'),
            hashlib.sha256).digest()
        )

    def get_timestamp(self):
        """ Returns the current timestamp in ISO 8601 format. """
        return datetime.utcnow().isoformat()

    def _enumerate_param(self, param, values):
        """ Builds a dictionary of an enumerated parameter.
            Takes any iterable and returns a dictionary.
            example:
              enumerate_param('MarketplaceIdList.Id', (123, 345, 4343))
            returns:
              {
                  MarketplaceIdList.Id.1: 123,
                  MarketplaceIdList.Id.2: 345,
                  MarketplaceIdList.Id.3: 4343
              }
        """
        # Shortcut for empty values
        if not values:
            return {}
        
        # Ensure this enumerated param ends in '.'
        if not param.endswith('.'):
            param = '{}.'.format(param)
        
        # Return a dict comprehension of the param, enumerated,
        # with its associated values.
        return {
            '{}{}'.format(param, idx+1): val
            for idx, val in enumerate(values)
        }
    
    def enumerate_params(self, params=None):
        """ Similar to enumerate_params.
            Takes a dict of params:
                each key is a param to be enumerated
                each value is a list of values for that param.
            For each param and values, runs _enumerate_param,
            returning a flat dict of all results
        """
        if params is None or not isinstance(params, dict):
            return {}
        
        params_output = {}
        for param, values in params.items():
            params_output.update(self._enumerate_param(param, values))
        
        return params_output


class Feeds(MWS):
    """ Amazon MWS Feeds API """

    ACCOUNT_TYPE = "Merchant"
    NEXT_TOKEN_OPERATIONS = [
        'GetFeedSubmissionList',
    ]

    def submit_feed(self, feed, feed_type, marketplaceids=None,
                    content_type="text/xml", purge='false'):
        """ Uploads a feed ( xml or .tsv ) to the seller's inventory.
            Can be used for creating/updating products on Amazon.
        """
        data = dict(
            Action='SubmitFeed',
            FeedType=feed_type,
            PurgeAndReplace=purge
        )
        data.update(self.enumerate_params({
            'MarketplaceIdList.Id.': marketplaceids,
        }))
        md = calc_md5(feed)
        return self.make_request(
            data,
            method="POST",
            body=feed,
            extra_headers={
                'Content-MD5': md, 'Content-Type': content_type
            }
        )

    def get_feed_submission_list(self, feedids=None, max_count=None,
                                 feedtypes=None, processingstatuses=None,
                                 fromdate=None, todate=None):
        """ Returns a list of all feed submissions submitted in the
            previous 90 days that match the query parameters.
        """

        data = dict(
            Action='GetFeedSubmissionList',
            MaxCount=max_count,
            SubmittedFromDate=fromdate,
            SubmittedToDate=todate,
        )
        data.update(self.enumerate_params({
           'FeedSubmissionIdList.Id': feedids,
           'FeedTypeList.Type.': feedtypes,
           'FeedProcessingStatusList.Status.': processingstatuses,
        }))
        return self.make_request(data)

    def get_feed_submission_count(self, feedtypes=None,
                                  processingstatuses=None, fromdate=None,
                                  todate=None):
        """ Returns a count of the feeds submitted in the previous 90 days. """
        data = dict(
            Action='GetFeedSubmissionCount',
            SubmittedFromDate=fromdate,
            SubmittedToDate=todate
        )
        data.update(self.enumerate_params({
            'FeedTypeList.Type.': feedtypes,
            'FeedProcessingStatusList.Status.': processingstatuses,
        }))
        return self.make_request(data)

    def cancel_feed_submissions(self, feedids=None, feedtypes=None,
                                fromdate=None, todate=None):
        """ Cancels one or more feed submissions and returns a count
            of the feed submissions that were canceled.
        """
        data = dict(
            Action='CancelFeedSubmissions',
            SubmittedFromDate=fromdate,
            SubmittedToDate=todate
        )
        data.update(self.enumerate_params({
            'FeedSubmissionIdList.Id.': feedids,
            'FeedTypeList.Type.': feedtypes,
        }))
        return self.make_request(data)

    def get_feed_submission_result(self, feedid):
        """ Returns the feed processing report and the Content-MD5 header. """
        data = dict(
            Action='GetFeedSubmissionResult',
            FeedSubmissionId=feedid
        )
        return self.make_request(data)


class Reports(MWS):
    """ Amazon MWS Reports API """

    ACCOUNT_TYPE = "Merchant"
    NEXT_TOKEN_OPERATIONS = [
        'GetReportRequestList',
        'GetReportScheduleList',
    ]
    
    ## REPORTS ###

    def get_report(self, report_id):
        """ Returns the contents of a report and the Content-MD5 header
            for the returned report body.
        """
        data = dict(
            Action='GetReport',
            ReportId=report_id
        )
        return self.make_request(data)

    def get_report_count(self, report_types=(), acknowledged=None,
                         fromdate=None, todate=None):
        """ Returns a count of the reports, created in the previous 90 days,
            with a status of _DONE_ and that are available for download.
        """
        data = dict(
            Action='GetReportCount',
            Acknowledged=acknowledged,
            AvailableFromDate=fromdate,
            AvailableToDate=todate
        )
        data.update(self.enumerate_params({
            'ReportTypeList.Type.': report_types,
        }))
        return self.make_request(data)

    def get_report_list(self, requestids=(), max_count=None, types=(),
                        acknowledged=None, fromdate=None, todate=None):
        """ Returns a list of reports that were created in the
            previous 90 days.
        """
        data = dict(
            Action='GetReportList',
            Acknowledged=acknowledged,
            AvailableFromDate=fromdate,
            AvailableToDate=todate,
            MaxCount=max_count
        )
        data.update(self.enumerate_params({
            'ReportRequestIdList.Id.': requestids,
            'ReportTypeList.Type.': types,
        }))
        return self.make_request(data)

    def get_report_request_count(self, report_types=(), processingstatuses=(),
                                 fromdate=None, todate=None):
        data = dict(
            Action='GetReportRequestCount',
            RequestedFromDate=fromdate,
            RequestedToDate=todate
        )
        data.update(self.enumerate_params({
            'ReportTypeList.Type.': report_types,
            'ReportProcessingStatusList.Status.': processingstatuses,
        }))
        return self.make_request(data)

    def get_report_request_list(self, requestids=(), types=(),
                                processingstatuses=(), max_count=None,
                                fromdate=None, todate=None):
        data = dict(
            Action='GetReportRequestList',
            MaxCount=max_count,
            RequestedFromDate=fromdate,
            RequestedToDate=todate
        )
        data.update(self.enumerate_params({
            'ReportRequestIdList.Id.': requestids,
            'ReportTypeList.Type.': types,
            'ReportProcessingStatusList.Status.': processingstatuses,
        }))
        return self.make_request(data)

    def request_report(self, report_type,
                       start_date=None, end_date=None,
                       marketplaceids=()):
        data = dict(
            Action='RequestReport',
            ReportType=report_type,
            StartDate=start_date,
            EndDate=end_date
        )
        data.update(self.enumerate_params({
            'MarketplaceIdList.Id.': marketplaceids,
        }))
        return self.make_request(data)


    ### ReportSchedule ###

    def get_report_schedule_list(self, types=()):
        data = dict(
            Action='GetReportScheduleList'
        )
        data.update(self.enumerate_params({
            'ReportTypeList.Type.': types,
        }))
        return self.make_request(data)

    def get_report_schedule_count(self, types=()):
        data = dict(
            Action='GetReportScheduleCount'
        )
        data.update(self.enumerate_params({
            'ReportTypeList.Type.': types,
        }))
        return self.make_request(data)


class Orders(MWS):
    """ Amazon Orders API """

    URI = "/Orders/2011-01-01"
    VERSION = "2011-01-01"
    NS = '{https://mws.amazonservices.com/Orders/2011-01-01}'
    NEXT_TOKEN_OPERATIONS = [
        'ListOrders',
        'ListOrderItems',
    ]

    def list_orders(self, marketplaceids, created_after=None,
                    created_before=None, lastupdatedafter=None,
                    lastupdatedbefore=None, orderstatus=(),
                    fulfillment_channels=(), payment_methods=(),
                    buyer_email=None, seller_orderid=None,
                    max_results='100'):
        """ Returns orders created or updated during a
            time frame that you specify.
        """
        data = dict(
            Action='ListOrders',
            CreatedAfter=created_after,
            CreatedBefore=created_before,
            LastUpdatedAfter=lastupdatedafter,
            LastUpdatedBefore=lastupdatedbefore,
            BuyerEmail=buyer_email,
            SellerOrderId=seller_orderid,
            MaxResultsPerPage=max_results,
        )
        data.update(self.enumerate_params({
            'OrderStatus.Status.': orderstatus,
            'MarketplaceId.Id.': marketplaceids,
            'FulfillmentChannel.Channel.': fulfillment_channels,
            'PaymentMethod.Method.': payment_methods,
        }))
        return self.make_request(data)

    def get_order(self, amazon_order_ids):
        """ Returns orders based on the AmazonOrderId values that you specify.
        """
        data = dict(
            Action='GetOrder'
        )
        data.update(self.enumerate_params({
            'AmazonOrderId.Id.': amazon_order_ids
        }))
        return self.make_request(data)

    def list_order_items(self, amazon_order_id):
        """ Returns order items based on the AmazonOrderId that you specify.
        """
        data = dict(
            Action='ListOrderItems',
            AmazonOrderId=amazon_order_id
        )
        return self.make_request(data)


class Products(MWS):
    """ Amazon MWS Products API """

    URI = '/Products/2011-10-01'
    VERSION = '2011-10-01'
    NS = '{http://mws.amazonservices.com/schema/Products/2011-10-01}'
    NEXT_TOKEN_OPERATIONS = []

    def list_matching_products(self, marketplaceid, query, contextid=None):
        """ Returns a list of products and their attributes, ordered by
            relevancy, based on a search query that you specify.
            
            Your search query can be a phrase that describes the product
            or it can be a product identifier such as a UPC, EAN, ISBN, or JAN.
        """
        data = dict(
            Action='ListMatchingProducts',
            MarketplaceId=marketplaceid,
            Query=query,
            QueryContextId=contextid
        )
        return self.make_request(data)

    def get_matching_product(self, marketplaceid, asins):
        """ Returns a list of products and their attributes, based on a list of
            ASIN values that you specify.
        """
        data = dict(
            Action='GetMatchingProduct',
            MarketplaceId=marketplaceid
        )
        data.update(self.enumerate_params({
            'ASINList.ASIN.': asins,
        }))
        return self.make_request(data)

    def get_matching_product_for_id(self, marketplaceid, type, ids):
        """ Returns a list of products and their attributes, based on a list of
            product identifier values
            (ASIN, SellerSKU, UPC, EAN, ISBN, GCID  and JAN)
            The identifier type is case sensitive.
            Added in Fourth Release, API version 2011-10-01
        """
        data = dict(
            Action='GetMatchingProductForId',
            MarketplaceId=marketplaceid,
            IdType=type
        )
        data.update(self.enumerate_params({
            'IdList.Id.': ids,
        }))
        return self.make_request(data)

    def get_competitive_pricing_for_sku(self, marketplaceid, skus):
        """ Returns the current competitive pricing of a product,
        based on the SellerSKU and MarketplaceId that you specify.
        """
        data = dict(
            Action='GetCompetitivePricingForSKU',
            MarketplaceId=marketplaceid
        )
        data.update(self.enumerate_params({
            'SellerSKUList.SellerSKU.': skus,
        }))
        return self.make_request(data)

    def get_competitive_pricing_for_asin(self, marketplaceid, asins):
        """ Returns the current competitive pricing of a product,
            based on the ASIN and MarketplaceId that you specify.
        """
        data = dict(
            Action='GetCompetitivePricingForASIN',
            MarketplaceId=marketplaceid
        )
        data.update(self.enumerate_params({
            'ASINList.ASIN.': asins,
        }))
        return self.make_request(data)

    def get_lowest_offer_listings_for_sku(self, marketplaceid, skus,
                                          condition="Any", excludeme="False"):
        """ Returns pricing information for the lowest-price active
            offer listings for a product, based on SellerSKU.
        """
        data = dict(
            Action='GetLowestOfferListingsForSKU',
            MarketplaceId=marketplaceid,
            ItemCondition=condition,
            ExcludeMe=excludeme
        )
        data.update(self.enumerate_params({
            'SellerSKUList.SellerSKU.', skus
        }))
        return self.make_request(data)

    def get_lowest_offer_listings_for_asin(self, marketplaceid, asins,
                                          condition="Any", excludeme="False"):
        """ Returns pricing information for the lowest-price active
            offer listings for a product, based on ASIN.
        """
        data = dict(
            Action='GetLowestOfferListingsForASIN',
            MarketplaceId=marketplaceid,
            ItemCondition=condition,
            ExcludeMe=excludeme
        )
        data.update(self.enumerate_params({
            'ASINList.ASIN.': asins,
        }))
        return self.make_request(data)

    def get_product_categories_for_sku(self, marketplaceid, sku):
        data = dict(
            Action='GetProductCategoriesForSKU',
            MarketplaceId=marketplaceid,
            SellerSKU=sku
        )
        return self.make_request(data)

    def get_product_categories_for_asin(self, marketplaceid, asin):
        data = dict(
            Action='GetProductCategoriesForASIN',
            MarketplaceId=marketplaceid,
            ASIN=asin
        )
        return self.make_request(data)

    def get_my_price_for_sku(self, marketplaceid, skus, condition=None):
        data = dict(
            Action='GetMyPriceForSKU',
            MarketplaceId=marketplaceid,
            ItemCondition=condition
        )
        data.update(self.enumerate_params({
            'SellerSKUList.SellerSKU.': skus,
        }))
        return self.make_request(data)

    def get_my_price_for_asin(self, marketplaceid, asins, condition=None):
        data = dict(
            Action='GetMyPriceForASIN',
            MarketplaceId=marketplaceid,
            ItemCondition=condition
        )
        data.update(self.enumerate_params({
            'ASINList.ASIN.': asins,
        }))
        return self.make_request(data)


class Sellers(MWS):
    """ Amazon MWS Sellers API """

    URI = '/Sellers/2011-07-01'
    VERSION = '2011-07-01'
    NS = '{http://mws.amazonservices.com/schema/Sellers/2011-07-01}'
    NEXT_TOKEN_OPERATIONS = [
        'ListMarketplaceParticipations',
    ]
    
    def list_marketplace_participations(self):
        """ Returns a list of marketplaces a seller can participate in and
            a list of participations that include seller-specific information
            in that marketplace. The operation returns only those marketplaces
            where the seller's account is in an active state.
        """
        data = dict(
            Action='ListMarketplaceParticipations'
        )
        return self.make_request(data)


#### Fulfillment APIs ####


class InboundShipments(MWS):
    """ Amazon MWS FulfillmentInboundShipment API  """
    URI = "/FulfillmentInboundShipment/2010-10-01"
    VERSION = '2010-10-01'
    NS = '{http://mws.amazonaws.com/FulfillmentInboundShipment/2010-10-01/}'
    NEXT_TOKEN_OPERATIONS = [
        'ListInboundShipments',
        'ListInboundShipmentItems',
    ]
    
    def get_prep_instructions_for_sku(self, skus=[], country_code=None):
        """ Returns labeling requirements and item preparation instructions
            to help you prepare items for an inbound shipment.
        """
        if country_code is None:
            country_code = 'US'
        data = dict(
            Action='GetPrepInstructionsForSKU',
            ShipToCountryCode=country_code,
        )
        data.update(self.enumerate_params({
            'SellerSKUList.ID.': skus,
        }))
        return self.make_request(data, "POST")
        
    def get_prep_instructions_for_asin(self, asins=[], country_code=None):
        """ Returns item preparation instructions to help with
            item sourcing decisions.
        """
        if country_code is None:
            country_code = 'US'
        data = dict(
            Action='GetPrepInstructionsForASIN',
            ShipToCountryCode=country_code,
        )
        data.update(self.enumerate_param({
            'ASINList.ID.': asins,
        }))
        return self.make_request(data, "POST")
        
    def get_package_labels(self, shipment_id, num_packages, page_type=None):
        """ Returns PDF document data for printing package labels for
            an inbound shipment.
        """
        data = dict(
            Action='GetPackageLabels',
            ShipmentId=shipment_id,
            PageType=page_type,
            NumberOfPackages=str(num_packages),
        )
        return self.make_request(data, "POST")
        
    def get_transport_content(self, shipment_id):
        """ Returns current transportation information about an
            inbound shipment.
        """
        data = dict(
            Action='GetTransportContent',
            ShipmentId=shipment_id
        )
        return self.make_request(data, "POST")
    
    def estimate_transport_request(self, shipment_id):
        """ Requests an estimate of the shipping cost for an inbound shipment.
        """
        data = dict(
            Action='EstimateTransportRequest',
            ShipmentId=shipment_id,
        )
        return self.make_request(data, "POST")
        
    def void_transport_request(self, shipment_id):
        """ Voids a previously-confirmed request to ship your inbound shipment
            using an Amazon-partnered carrier.
        """
        data = dict(
            Action='VoidTransportRequest',
            ShipmentId=shipment_id
        )
        return self.make_request(data, "POST")
        
    def get_bill_of_lading(self, shipment_id):
        """ Returns PDF document data for printing a bill of lading
            for an inbound shipment.
        """
        data = dict(
            Action='GetBillOfLading',
            ShipmentId=shipment_id,
        )
        return self.make_request(data, "POST")
    
    def list_inbound_shipments(self, shipment_ids=None,
                               shipment_statuses=None,
                               last_updated_after=None,
                               last_updated_before=None):
        """ Returns list of shipments based on statuses, IDs, and/or
            before/after datetimes
        """
        data = dict(
            Action='ListInboundShipments',
            LastUpdatedAfter=last_updated_after,
            LastUpdatedBefore=last_updated_before,
        )
        data.update(self.enumerate_params({
            'ShipmentStatusList.member.': shipment_statuses,
            'ShipmentIdList.member.': shipment_ids,
        }))
        return self.make_request(data, "POST")
    
    def list_inbound_shipment_items(self, shipment_id=None,
                                    last_updated_after=None,
                                    last_updated_before=None):
        """ Returns list of items within inbound shipments and/or
            before/after datetimes.
        """
        data = dict(
            Action='ListInboundShipmentItems',
            ShipmentId=shipment_id,
            LastUpdatedAfter=last_updated_after,
            LastUpdatedBefore=last_updated_before,
        )
        return self.make_request(data, "POST")


class Inventory(MWS):
    """ Amazon MWS Inventory Fulfillment API """

    URI = '/FulfillmentInventory/2010-10-01'
    VERSION = '2010-10-01'
    NS = "{http://mws.amazonaws.com/FulfillmentInventory/2010-10-01}"
    NEXT_TOKEN_OPERATIONS = [
        'ListInventorySupply',
    ]
    
    def list_inventory_supply(self, skus=(), datetime=None,
                              response_group='Basic'):
        """ Returns information on available inventory """

        data = dict(Action='ListInventorySupply',
                    QueryStartDateTime=datetime,
                    ResponseGroup=response_group,
                    )
        data.update(self.enumerate_params({
            'SellerSkus.member.': skus,
        }))
        return self.make_request(data, "POST")


class OutboundShipments(MWS):
    URI = "/FulfillmentOutboundShipment/2010-10-01"
    VERSION = "2010-10-01"
    NEXT_TOKEN_OPERATIONS = [
        'ListAllFulfillmentOrders',
    ]
    # To be completed


class Recommendations(MWS):

    """ Amazon MWS Recommendations API """

    URI = '/Recommendations/2013-04-01'
    VERSION = '2013-04-01'
    NS = "{https://mws.amazonservices.com/Recommendations/2013-04-01}"

    def get_last_updated_time_for_recommendations(self, marketplaceid):
        """ Checks whether there are active recommendations for each
            category for the given marketplace, and if there are, returns
            the time when recommendations were last updated for each category.
        """

        data = dict(
            Action='GetLastUpdatedTimeForRecommendations',
            MarketplaceId=marketplaceid,
        )
        return self.make_request(data, "POST")

    def list_recommendations(self, marketplaceid, recommendationcategory=None):
        """ Returns your active recommendations for a specific category or
            for all categories for a specific marketplace.
        """

        data = dict(
            Action="ListRecommendations",
            MarketplaceId=marketplaceid,
            RecommendationCategory=recommendationcategory
        )
        return self.make_request(data, "POST")
