package verifiedpermissions;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.services.verifiedpermissions.VerifiedPermissionsClient;
import software.amazon.awssdk.services.verifiedpermissions.model.PolicyDefinitionItem;
import software.amazon.awssdk.services.verifiedpermissions.model.PolicyEffect;
import software.amazon.awssdk.services.verifiedpermissions.model.PolicyFilter;
import software.amazon.awssdk.services.verifiedpermissions.model.PolicyItem;
import software.amazon.awssdk.services.verifiedpermissions.model.PolicyType;
import software.amazon.awssdk.services.verifiedpermissions.model.ValidationException;

@Slf4j
class ListPoliciesTest {

	private static final String POLICY_STORE_ID = "Y5ey8fXL8kZSSGEMG3dBXf";
	
	private static final String POLICY_TEMPLATE_ID_AAA = "FVcL3CFMt1LB97UD5Cu8tx";
	private static final String POLICY_TEMPLATE_ID_BBB = "NAu1UNgK1mNxFC5zbFdP1t";
	
	private VerifiedPermissionsClient client = VerifiedPermissionsClient.create();
	
	@Test
	void StaticPolicy__Principal_EntityTypeのみ指定() {
		
		Consumer<PolicyFilter.Builder> f = (filter -> filter
				.principal(principal -> principal.identifier(id -> id.entityType("NAMESPACE::Group"))));
		
		try {
			listPolicies(f);
			fail();
		} catch(ValidationException e) {
			log.info(e.getMessage());
		}
	}
	
	@Test
	void StaticPolicy__Principal_両方指定() {
		
		Consumer<PolicyFilter.Builder> f = (filter -> filter
				.principal(principal -> principal.identifier(id -> id.entityType("NAMESPACE::Group").entityId("group1"))));
		
		List<PolicyItem> list =	listPolicies(f);
		assertEquals(3, list.size());
		list.forEach(policy -> log.info("{}", policy));
		
		int pi = 0;
		assertEquals(POLICY_STORE_ID, list.get(pi).policyStoreId());
		assertNotNull(list.get(pi).policyId());
		assertEquals(POLICY_STORE_ID, list.get(pi).policyStoreId());
		assertEquals(PolicyType.STATIC, list.get(pi).policyType());
		assertEquals("NAMESPACE::Group", list.get(pi).principal().entityType());
		assertEquals("group1", list.get(pi).principal().entityId());
		assertEquals("NAMESPACE::Application", list.get(pi).resource().entityType());
		assertEquals("application", list.get(pi).resource().entityId());
		assertEquals(3, list.get(pi).actions().size());
		int ai = 0;
		assertEquals("NAMESPACE::Action", list.get(pi).actions().get(ai).actionType());
		assertEquals("function1", list.get(pi).actions().get(ai).actionId());
		ai = 1;
		assertEquals("NAMESPACE::Action", list.get(pi).actions().get(ai).actionType());
		assertEquals("function2", list.get(pi).actions().get(ai).actionId());
		ai = 2;
		assertEquals("NAMESPACE::Action", list.get(pi).actions().get(ai).actionType());
		assertEquals("function3", list.get(pi).actions().get(ai).actionId());
		assertEquals(PolicyDefinitionItem.Type.STATIC, list.get(pi).definition().type());
		assertNull(list.get(pi).definition().templateLinked());
		assertNotNull(list.get(pi).createdDate());
		assertNotNull(list.get(pi).lastUpdatedDate());
		assertEquals(PolicyEffect.PERMIT, list.get(pi).effect());
		
		pi = 1;
		assertEquals(POLICY_STORE_ID, list.get(pi).policyStoreId());
		assertNotNull(list.get(pi).policyId());
		assertEquals(POLICY_STORE_ID, list.get(pi).policyStoreId());
		assertEquals(PolicyType.TEMPLATE_LINKED, list.get(pi).policyType());
		assertEquals("NAMESPACE::Group", list.get(pi).principal().entityType());
		assertEquals("group1", list.get(pi).principal().entityId());
		assertEquals("NAMESPACE::Aaa", list.get(pi).resource().entityType());
		assertEquals("aaa2", list.get(pi).resource().entityId());
		assertEquals(1, list.get(pi).actions().size());
		ai = 0;
		assertEquals("NAMESPACE::Action", list.get(pi).actions().get(ai).actionType());
		assertEquals("memberOf", list.get(pi).actions().get(ai).actionId());
		assertEquals(PolicyDefinitionItem.Type.TEMPLATE_LINKED, list.get(pi).definition().type());
		assertEquals(POLICY_TEMPLATE_ID_AAA, list.get(pi).definition().templateLinked().policyTemplateId());
		assertEquals("NAMESPACE::Group", list.get(pi).definition().templateLinked().principal().entityType());
		assertEquals("group1", list.get(pi).definition().templateLinked().principal().entityId());
		assertEquals("NAMESPACE::Aaa", list.get(pi).definition().templateLinked().resource().entityType());
		assertEquals("aaa2", list.get(pi).definition().templateLinked().resource().entityId());
		assertNotNull(list.get(pi).createdDate());
		assertNotNull(list.get(pi).lastUpdatedDate());
		assertEquals(PolicyEffect.PERMIT, list.get(pi).effect());
	}
	
	@Test
	void StaticPolicy__Resource_EntityTypeのみ指定() {
		
		Consumer<PolicyFilter.Builder> f = (filter -> filter
				.resource(resource -> resource.identifier(id -> id.entityType("NAMESPACE::Application"))));
		
		try {
			listPolicies(f);
			fail();
		} catch(ValidationException e) {
			log.info(e.getMessage());
		}
	}
	
	@Test
	void StaticPolicy__Resource_両方指定() {
		
		Consumer<PolicyFilter.Builder> f = (filter -> filter
				.principal(resource -> resource.identifier(id -> id.entityType("NAMESPACE::Application").entityId("application"))));
		
		List<PolicyItem> list =	listPolicies(f);
		assertEquals(3, list.size());
		list.forEach(policy -> log.info("{}", policy));
	}
	
	@Test
	void StaticPolicy__Principal_Resource_両方指定() {
		
		Consumer<PolicyFilter.Builder> f = (filter -> filter
				.principal(principal -> principal.identifier(id -> id.entityType("NAMESPACE::Group").entityId("group1")))
				.resource(resource -> resource.identifier(id -> id.entityType("NAMESPACE::Application").entityId("application"))));
		
		List<PolicyItem> list =	listPolicies(f);
		assertEquals(1, list.size());
		list.forEach(policy -> log.info("{}", policy));
	}
	
	@Test
	void LinkedPolicy__TemplateId() {
		
		Consumer<PolicyFilter.Builder> f = (filter -> filter
				.policyTemplateId(POLICY_TEMPLATE_ID_AAA));
		
		List<PolicyItem> list =	listPolicies(f);
		assertEquals(3, list.size());
		list.forEach(policy -> log.info("{}", policy));
	}
	
	@Test
	void LinkedPolicy__Principal_両方指定() {
		
		Consumer<PolicyFilter.Builder> f = (filter -> filter
				.policyTemplateId(POLICY_TEMPLATE_ID_AAA)
				.principal(principal -> principal.identifier(id -> id.entityType("NAMESPACE::Group").entityId("group1"))));
		
		List<PolicyItem> list =	listPolicies(f);
		assertEquals(2, list.size());
		list.forEach(policy -> log.info("{}", policy));
	}
	
	private List<PolicyItem> listPolicies(Consumer<PolicyFilter.Builder> filter) {
		List<PolicyItem> result = new ArrayList<PolicyItem>();
		client.listPoliciesPaginator(req -> req.policyStoreId(POLICY_STORE_ID).filter(filter)).forEach(response -> {
			result.addAll(response.policies());
		});
		return result;
	}
}
