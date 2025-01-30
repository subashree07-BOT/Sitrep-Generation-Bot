import streamlit as st
from langchain_community.callbacks.manager import get_openai_callback
from langchain_openai import ChatOpenAI
from langchain.chains import LLMChain
from langchain.prompts.chat import ChatPromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate
import openai
from typing import Dict, Optional
import json
import logging
import os
import re  

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityAdvisor:
    def __init__(self):
        self.openai_api_key = st.secrets["OPENAI_API_KEY"]
        if not self.openai_api_key:
            raise ValueError("OpenAI API key not found in environment variables. Please set OPENAI_API_KEY.")
        
        self.llm = ChatOpenAI(
            model_name="gpt-4o-mini",
            temperature=0.1,
            openai_api_key=self.openai_api_key
        )

    
    def process_query(self, query: str):
        """Extract name and clean query from timestamp format"""
        pattern = r'^([^,]+),\s*(?:[^,]+,\s*\d+\s+\w+\s+\d+\s+[\d:]+\s+\w+)\s*\n(.+)$'
        match = re.match(pattern, query.strip(), re.DOTALL)
        
        if match:
            name, content = match.groups()
            return name.strip(), content.strip()
        return None, query.strip()

    def generate_response(self, sitrep: str, query: str) -> Dict:
        """
        Generates responses for security-related queries based on sitrep analysis
        """
        try:
            name, cleaned_query = self.process_query(query)
            greeting = f"Hey {name}," if name else "Hey,"
            
            # Handle empty or simple acknowledgment queries
            if not cleaned_query or cleaned_query.lower().startswith(('thank', 'ok', 'got it')):
                return {
                    "response": f"{greeting}\n\nMessage received. Thank you! Gradient Cyber Team!"
                }


            response_prompt = ChatPromptTemplate.from_messages([
                SystemMessagePromptTemplate.from_template(f"""
    You are an experienced cyber security analyst handling the role from a Security operations center perspective.
    When I provide a message, it contains the summary of a "sitrep" which is a situational report of a particular
    security incident or event.

"First, carefully review all provided information, including situation reports and customer queries. Then conduct a thorough analysis of the information to understand the requirements. Finally, provide a comprehensive and appropriate response that addresses the customer's specific needs."

This emphasizes the three key steps:
1. Review all input information
2. Analyze the requirements
3. Provide a targeted response

    Response Guidelines:
    1. First analyze the sitrep and client query:
       - If client confirms normal/expected behavior → Provide concise, straightforward response
       - If client needs technical guidance → Provide detailed instructions
       - If client reports an issue → Provide thorough analysis and recommendations
       - If query relates to existing sitrep recommendations → Build upon and enhance them
       - Identify any overlap between query and sitrep content
    2. Response Structure Based on Query Type:
       For Straightforward Confirmations:
       - Keep responses concise and direct
       - Focus only on necessary next steps
       - Mirror the client's level of technical detail
       - Do NOT suggest setting up new alerts or monitoring systems
       For Complex or Technical Queries:
       - Provide complete, navigable instructions
       - Include specific UI paths and prerequisites
       - Organize information logically
       - Keep technical explanations clear
       For Queries About Existing Recommendations:
       - Acknowledge existing information first
       - Build upon basic recommendations with specific implementation details
       - Add practical, actionable steps not mentioned in sitrep
       - Focus on HOW to implement rather than WHAT to implement
       - Provide real-world examples or best practices
    3. Always maintain:
       - Professional tone
       - Clear, direct language
       - Only relevant information
       - Connection to specific context from sitrep
       - Value-adding insights beyond basic recommendations
       - Proper greeting and closing
       - If recommendations exist in sitrep, don't just repeat them - enhance them with specific implementation details and then retaining them again.This is only for actionable items queries. For example: these are type of actionable items queries that can be implemented:
            What should we do to prevent malware infections?
            How can we improve our phishing prevention measures?
       - Use appropriate closing based on interaction type
                   Closing Format:
                   - Must use one of these exact closings based on interaction type:
                     * Questions: "We hope this answers your question. Thank you! Gradient Cyber Team!"
                     * Confirmations: "Thank you for confirming. Gradient Cyber Team!"
                     * Information: "Thank you for the information. Gradient Cyber Team!"
                     * Updates: "Thank you for the update. Gradient Cyber Team!"
    Remember:
    - Match response complexity to client's query style - if they're brief, be brief; if they need details, be thorough
    - If recommendations exist in sitrep, don't just repeat them - enhance them with specific implementation details
    - Keep responses brief as they are primarily provided as part of a web interface or email
     CRITICAL FOR ALERT RESPONSES:
  * Never assume alert preferences based on client statements
  * Always get explicit confirmation for alert changes
  * Present clear options for future monitoring
  * Avoid making definitive statements about alert changes without confirmation
    Always start with "{greeting}" and end with the appropriate closing.
    """),
    HumanMessagePromptTemplate.from_template("""
    Sitrep: {sitrep}
    Query: {query}
    """)
])

            chain = LLMChain(llm=self.llm, prompt=response_prompt)
            response = chain.run(sitrep=sitrep, query=cleaned_query)
            
            
            # Remove any potential greeting patterns from the response
            response = re.sub(r'^Hey[^,]*,\s*', '', response.strip())
            
            # Add our controlled greeting
            response = f"{greeting}\n\n{response}"
            return {
                "response": response.strip()
            }
        except Exception as e:
            logger.error(f"Error generating response: {str(e)}")
            return {
                "response": "Error generating response. Please try again."
            }
def main():
    st.set_page_config(page_title="Security Advisor", layout="wide")
    
    st.title("Security Advisory System")
    
    advisor = SecurityAdvisor()
    
    alert_context = st.text_area(
        "Situation Report (Sitrep)",
        placeholder="Enter the security incident/event summary here...",
        height=150
    )
    
    customer_query = st.text_area(
        "Customer Query",
        placeholder="Enter the customer's question here...",
        height=100
    )
    
    if st.button("Generate Response", type="primary"):
        if not alert_context or not customer_query:
            st.error("Please provide both sitrep and query.")
            return
            
        with st.spinner("Analyzing sitrep and generating response..."):
            with get_openai_callback() as cb:
                result = advisor.generate_response(alert_context, customer_query)
                
                st.markdown("### Response:")
                st.markdown(result["response"])
                
                

if __name__ == "__main__":
    main()
