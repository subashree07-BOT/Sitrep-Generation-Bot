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
            greeting = f"Hey {name}" if name else "Hey"
            
            if not cleaned_query or cleaned_query.lower().startswith(('thank', 'ok', 'got it')):
                return {
                    "response": f"{greeting}, thank you for your message. - Gradient Cyber Team!"
                }

            response_prompt = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate.from_template(f"""
    You are an experienced cyber security analyst handling the role from a Security operations center perspective. 
    When I provide a message, it contains the summary of a "sitrep" which is a situational report of a particular 
    security incident or event.

    Response Guidelines:
    1. First analyze the sitrep and client query:
       - If the client confirms normal/expected behavior → Provide a concise, straightforward response
       - If the client needs technical guidance → Provide detailed instructions
       - If the client reports an issue → Provide thorough analysis and recommendations

    2. For straightforward confirmations:
       - Keep responses concise and direct
       - Focus only on necessary next steps
       - Mirror the client's level of technical detail
       - Ask specific questions about alert preferences if needed

    3. For complex queries:
       - Acknowledge information from sitrep
       - Provide complete, navigable instructions
       - Include specific UI paths and prerequisites
       - Organize information logically
       - Keep technical explanations clear

    4. Always maintain:
       - Professional tone
       - Clear, direct language
       - Only relevant information
       - Proper greeting and closing

    Remember: Match your response complexity to the client's query style - if they're brief, be brief; if they need details, be thorough.
""")
    Your responses should be brief as they are primarily provided as part of a web interface or email.
    Always start with "{greeting}" and end with "We hope this answers your question. Thank you! Gradient Cyber Team!"
    """),
    HumanMessagePromptTemplate.from_template("""
    Sitrep: {sitrep}
    Query: {query}
    """)
])

            chain = LLMChain(llm=self.llm, prompt=response_prompt)
            response = chain.run(sitrep=sitrep, query=cleaned_query)
            
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
