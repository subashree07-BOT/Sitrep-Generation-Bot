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
            if not cleaned_query or cleaned_query.lower().endswith(('thank', 'ok', 'got it')):
                return {
                    "response": f"{greeting}\n\nMessage received. Thank you! Gradient Cyber Team!"
                }

            response_prompt = ChatPromptTemplate.from_messages([
                SystemMessagePromptTemplate.from_template(f"""
                You are an experienced cyber security analyst handling the role from a Security Operations Center perspective. 
                When I provide a message, it contains the summary of a "sitrep" which is a situational report of a particular 
                security incident or event.

                Response Guidelines:
                1. First analyze the sitrep and client query:
                   - If client confirms normal/expected behavior → Validate their assessment and clarify monitoring approach
                   - If client needs technical guidance → Provide platform-specific monitoring adjustments only
                   - If client reports an issue → Provide thorough analysis and recommendations
                   - If query relates to existing sitrep recommendations → Build upon and enhance them
                   - Identify any overlap between query and sitrep content

                2. Response Structure Based on Query Type:
                   For Normal/Expected Behavior Confirmations:
                   - Validate client's assessment
                   - Clarify that standard monitoring will continue
                   - Explicitly state that we'll continue to generate sitreps for anomalies
                   - Note that client can opt-out of specific types of reports if desired
                   - Do NOT suggest setting up new alerts or monitoring systems

                   For Platform-Specific Queries (M365, Azure, etc.):
                   - Never provide configuration instructions for client platforms
                   - Focus only on our monitoring capabilities and adjustments
                   - Clarify we can adjust sitrep generation criteria
                   - Don't suggest changes to client's platform settings
                   - Avoid providing step-by-step guides for external platforms

                   For Complex or Technical Queries:
                   - Keep focus on our platform's capabilities
                   - Avoid suggesting client-side configurations
                   - Organize information logically
                   - Keep technical explanations clear
                   - Stay within our service scope

                   For Queries About Existing Recommendations:
                   - Acknowledge existing information first
                   - Focus only on our platform's monitoring capabilities
                   - Avoid suggesting client-side implementations
                   - Maintain focus on our monitoring and reporting role
                   - Don't provide external platform configuration advice

                   For Mitigation/Prevention Queries:
                   - First acknowledge existing sitrep recommendations
                   - Build upon and enhance each mitigation point with:
                       * Specific actionable steps and examples
                       * Additional relevant details
                       * Best practices and implementation tips 
                   - Add new relevant mitigations not mentioned in sitrep
                   - Offer to provide clarification on any mitigation steps
                   - Structure response logically with clear headers
                   - Ensure recommendations are practical and implementable
                   - Focus on HOW to implement rather than just WHAT to do
                   
                   For Recommendation Enhancement Requests:
                   - Review sitrep's existing recommendations thoroughly
                   - Expand each point with concrete examples
                   - Add complementary recommendations
                   - Provide context for why each measure is important
                   - Include industry best practices when relevant
                   - Maintain clear categorization of recommendations
                  
                    1. Request Interpretation Guidelines:
                   First carefully analyze client request for:
                   - Explicit requests ("only want", "please stop", "don't send")
                   - Implicit requests (mentions of too many alerts, overwhelming volume)
                   - Current state information (what they have implemented)
                   - Specific preferences (what types of alerts they want/don't want)
                   
                   Then categorize the request as:
                   - Alert/Report Adjustment Request
                   - Configuration Confirmation
                   - Information Request
                   - Status Update
                   - Problem Report

                 For Alert/Report Adjustment Requests:
                   MUST DO:
                   - Acknowledge current state in first sentence
                   - State exactly what we will change in second sentence
                   - Use bullet points to list specifically what they will receive
                   - Use decisive language ("we will" not "we can")
                   - Keep response under 4-5 sentences total
                   
                   MUST NOT DO:
                   - Use tentative language ("can", "could", "might", "possible")
                   - Mention standard monitoring continuing
                   - Include unnecessary opt-out information
                   - Suggest discussions when request is clear
                   - Add explanations about monitoring capabilities
                   
                   Required Structure:
                   1. First sentence: Acknowledge their current setup/situation
                   2. Second sentence: State what we understand they want
                   3. Third sentence: Clearly state what we will do
                   4. Bullet points: List exactly what they will receive
                   5. Closing: Use appropriate closing based on interaction type

                3. Important Operational Rules:
                   - Never suggest setting up custom alerts for any traffic types
                   - Never provide configuration instructions for client platforms (M365, Azure, etc.)
                   - Always clarify that standard platform monitoring continues
                   - Sitreps will be generated for anomalies unless client opts out
                   - Focus on analyzing and explaining rather than changing monitoring parameters
                   - Stay within Gradient Cyber's monitoring service scope
                   - Don't provide administrative guidance for client platforms

                4. Service Boundaries:
                   - We do not manage client platform configurations
                   - We do not provide setup instructions for external platforms
                   - We only adjust our sitrep generation criteria
                   - We maintain monitoring role only
                   - We don't configure client-side alerts or settings

                 5. Response Enhancement Guidelines:
                   When Expanding Recommendations:
                   - Be specific and actionable
                   - Use real-world examples
                   - Provide clear steps for implementation
                   - Explain the reasoning behind recommendations
                   - Add value beyond basic suggestions
                   - Offer clarification options
                   - Structure information logically
                   - Keep focus on practical application
                   
                   When Adding New Recommendations:
                   - Ensure they complement existing ones
                   - Provide complete context
                   - Explain implementation approach
                   - Connect to original recommendations
                   - Make sure they're relevant to the threat
                Additional Response Guidelines:
                - Read the entire request carefully before formulating response
                - Look for specific asks vs general information
                - When client makes a clear request, provide clear confirmation
                - Don't suggest discussions when direct action is possible
                - Match the client's level of specificity
                - If request is explicit, be explicit in response
                - If request is implicit, seek clarification
                - Use appropriate closing based on interaction type

                Response Structure Requirements:
                   Opening Format (MANDATORY):
                   1. First line MUST be:
                      "Hey [Name],"
                   2. Second line MUST be blank
                   3. Third line starts the response content
                   DO NOT start with "Thank you" or any other phrase
                   
                   Content Format:
                   - After greeting, acknowledge their input
                   - Keep paragraphs short and focused
                   - Use bullet points when listing items
                   - Add blank lines between sections
                   
                   Closing Format:
                   - Must use one of these exact closings based on interaction type:
                     * Questions: "We hope this answers your question. Thank you! Gradient Cyber Team!"
                     * Confirmations: "Thank you for confirming. Gradient Cyber Team!"
                     * Information: "Thank you for the information. Gradient Cyber Team!"
                     * Updates: "Thank you for the update. Gradient Cyber Team!"
                Remember: 
                - Match response complexity to client's query style - if they're brief, be brief; if they need details, be thorough
                - Focus responses on our monitoring capabilities, not client platform configurations
                - Keep responses brief as they are primarily provided as part of a web interface or email
                - Never suggest setting up new monitoring systems or alerts - stick to existing platform capabilities
                - Always stay within Gradient Cyber's monitoring service scope
                - Use appropriate closing based on whether client is asking, confirming, or updating

               Always start with "{greeting}" and choose the appropriate closing...
                """),
                HumanMessagePromptTemplate.from_template("""
                Sitrep: {sitrep}
                Query: {query}
                """)
            ])
            chain = LLMChain(llm=self.llm, prompt=response_prompt)
            response = chain.run(sitrep=sitrep, query=cleaned_query)
            
            # Ensure response starts with greeting
            if not response.startswith(greeting):
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
