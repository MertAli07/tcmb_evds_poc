import json
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def validate_date_format(date_string):
    """Validate DD-MM-YYYY format"""
    try:
        datetime.strptime(date_string, '%d-%m-%Y')
        return True
    except ValueError:
        return False

def lambda_handler(event, context):
    """
    Lambda function for Bedrock Agent action group to structure EVDS request
    
    Expected event structure from Bedrock Agent:
    {
        "messageVersion": "1.0",
        "agent": {...},
        "inputText": "...",
        "sessionId": "...",
        "actionGroup": "...",
        "apiPath": "/structure-evds-request",
        "httpMethod": "POST",
        "parameters": [
            {"name": "startDate", "type": "string", "value": "01-01-2024"},
            {"name": "endDate", "type": "string", "value": "31-12-2024"},
            ...
        ],
        "requestBody": {
            "content": {
                "application/json": {
                    "properties": [...]
                }
            }
        }
    }
    """
    
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract parameters from the event
        # Parameters can come from either 'parameters' array or 'requestBody'
        parameters = event.get('parameters', [])
        
        # If parameters array is empty, check requestBody
        if not parameters and 'requestBody' in event:
            request_body = event.get('requestBody', {})
            content = request_body.get('content', {})
            app_json = content.get('application/json', {})
            parameters = app_json.get('properties', [])
        
        # Convert parameters list to dictionary
        params_dict = {param['name']: param['value'] for param in parameters}
        
        # Extract user's original question/input text
        user_question = event.get('inputText', '')
        
        # Extract and validate each field
        start_date = params_dict.get('startDate', '')
        end_date = params_dict.get('endDate', '')
        aggregation_type = params_dict.get('aggregationType', '')
        frequency = params_dict.get('frequency', '')
        formulas = params_dict.get('formulas', '')
        
        # Validation
        errors = []
        
        if not start_date or not validate_date_format(start_date):
            errors.append("startDate must be in DD-MM-YYYY format")
        
        if not end_date or not validate_date_format(end_date):
            errors.append("endDate must be in DD-MM-YYYY format")
        
        valid_aggregations = ['avg', 'min', 'max', 'first', 'last', 'sum']
        if aggregation_type not in valid_aggregations:
            errors.append(f"aggregationType must be one of: {', '.join(valid_aggregations)}")
        
        valid_frequencies = ['1', '2', '3', '4', '5', '6']
        if frequency not in valid_frequencies:
            errors.append("frequency must be between 1-6 (1: Daily, 2: Weekly, 3: Monthly, 4: Quarterly, 5: Semiannual, 6: Annual)")
        
        valid_formulas = ['0', '1', '2', '3']
        if formulas not in valid_formulas:
            errors.append("formulas must be between 0-3 (0: Level, 1: % Change, 2: Difference, 3: Year-over-year % Change)")
        
        # If there are validation errors
        if errors:
            response_body = {
                "status": "error",
                "message": "Validation failed",
                "errors": errors
            }
            http_status = 400
        else:
            # Create structured output
            structured_data = {
                "userQuestion": user_question,
                "startDate": start_date,
                "endDate": end_date,
                "aggregationType": aggregation_type,
                "frequency": frequency,
                "formulas": formulas
            }
            
            response_body = {
                "status": "success",
                "message": "EVDS request parameters validated and structured successfully",
                "data": structured_data,
                "metadata": {
                    "frequencyDescription": get_frequency_description(frequency),
                    "formulaDescription": get_formula_description(formulas),
                    "aggregationDescription": aggregation_type
                }
            }
            http_status = 200
        
        # Format response for Bedrock Agent - CORRECT FORMAT
        action_response = {
            "messageVersion": "1.0",
            "response": {
                "actionGroup": event.get("actionGroup", ""),
                "apiPath": event.get("apiPath", ""),
                "httpMethod": event.get("httpMethod", "POST"),
                "httpStatusCode": http_status,
                "responseBody": {
                    "application/json": {
                        "body": json.dumps(response_body, ensure_ascii=False)
                    }
                }
            }
        }
        
        logger.info(f"Returning response: {json.dumps(action_response)}")
        
        return action_response
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        
        error_response = {
            "messageVersion": "1.0",
            "response": {
                "actionGroup": event.get("actionGroup", ""),
                "apiPath": event.get("apiPath", ""),
                "httpMethod": event.get("httpMethod", "POST"),
                "httpStatusCode": 500,
                "responseBody": {
                    "application/json": {
                        "body": json.dumps({
                            "status": "error",
                            "message": f"Internal error: {str(e)}"
                        })
                    }
                }
            }
        }
        
        return error_response

def get_frequency_description(frequency):
    """Get human-readable frequency description"""
    frequency_map = {
        '1': 'Daily',
        '2': 'Weekly',
        '3': 'Monthly',
        '4': 'Quarterly',
        '5': 'Semiannual',
        '6': 'Annual'
    }
    return frequency_map.get(frequency, 'Unknown')

def get_formula_description(formula):
    """Get human-readable formula description"""
    formula_map = {
        '0': 'Level',
        '1': '% Change',
        '2': 'Difference',
        '3': 'Year-over-year % Change'
    }
    return formula_map.get(formula, 'Unknown')