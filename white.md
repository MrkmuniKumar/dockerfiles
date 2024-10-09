## **White Paper: Advantages and Disadvantages of Deploying On-Prem Applications Using EKS Agents vs. On-Prem Kubernetes Agents**

### **1. Introduction**

In the rapidly evolving landscape of cloud-native technologies, Kubernetes and Azure DevOps (ADO) pipelines are essential components for streamlining application deployment. The decision between hosting ADO agents on an Amazon Elastic Kubernetes Service (EKS) cluster or an on-prem Kubernetes cluster has significant implications for performance, security, latency, and operational complexity.

This white paper explores the benefits and challenges of using ADO agents in EKS versus running agents on an on-prem Kubernetes cluster, with a focus on how these approaches impact the deployment of on-premises applications. We will examine key factors such as traffic flow, security, and deployment efficiency to provide clarity on which approach aligns best with our objectives.

### **2. Key Concepts**

#### **2.1 Azure DevOps (ADO) Agents**
ADO agents are responsible for executing pipeline tasks like retrieving code, running tests, building artifacts, and deploying applications. These agents can be hosted in the cloud (e.g., EKS) or within a local on-premises Kubernetes cluster.

#### **2.2 Amazon Elastic Kubernetes Service (EKS)**
EKS is AWS's managed Kubernetes service, providing a scalable platform for running containerized applications without the need to manage the Kubernetes control plane.

#### **2.3 On-Premises Kubernetes**
On-prem Kubernetes refers to hosting and managing a Kubernetes cluster in our own data center, giving us full control over the environment, infrastructure, and security.

### **3. Deployment Models: EKS vs. On-Prem Kubernetes Agents**

For on-prem application deployments, we can either run ADO agents in an EKS cluster (cloud-based) or on our own on-prem Kubernetes cluster (local infrastructure). Each approach introduces specific advantages and disadvantages that affect continuous deployment (CD) operations.

### **4. Traffic Flow and Latency Considerations**

#### **4.1 Traffic Flow in EKS-Based ADO Agents**
- **Multi-Hop Traffic Flow:** When using EKS-based ADO agents to deploy on-prem applications, the traffic does not flow directly between ADO and EKS. Instead, the traffic typically involves multiple hops:
  1. From **ADO** to our **on-prem infrastructure** (e.g., retrieving artifacts or connecting to services).
  2. From **on-prem back to EKS** for execution of the pipeline tasks.
  3. From **EKS back to on-prem** for deployment to the final on-prem environment.
  
  This multi-hop traffic introduces additional latency due to the need to traverse multiple networks (cloud and on-prem).

- **Increased Latency:** The increased network overhead from multiple hops adds latency, particularly in deployments targeting on-prem resources. This can be problematic for applications that require rapid deployment or time-sensitive updates.

#### **4.2 Traffic Flow in On-Prem Kubernetes Agents**
- **Direct Traffic Flow:** By running ADO agents in our on-prem Kubernetes cluster, traffic between ADO and the target infrastructure flows more directly. Communication stays largely within the internal network, avoiding external cloud hops.
- **Lower Latency:** The direct nature of this communication results in reduced latency for on-prem deployments, improving deployment speed for applications that need to remain within our data center.

### **5. Security and Control**

#### **5.1 Security in EKS-Based ADO Agents**
- **Shared Responsibility Model:** EKS security is shared between AWS and our team. While AWS manages the security of the infrastructure, we are responsible for securing the workloads and data. Managing the multiple communication paths between ADO, EKS, and on-prem environments introduces more complexity.
- **Multiple Attack Surfaces:** The multi-hop traffic between ADO, EKS, and on-prem infrastructure increases the attack surface. Each hop (e.g., between the cloud and on-prem) requires secure network configurations, such as VPNs or VPC peering, to ensure encrypted and secure communication.

#### **5.2 Security in On-Prem Kubernetes Agents**
- **Full Control Over Security:** Running ADO agents on-prem gives us complete control over security policies and access controls. With traffic staying within the internal network, the risk of external breaches is reduced. There is less need for complex VPNs or cloud-specific security configurations.
- **Lower Risk:** Without the need to route traffic through external cloud services, we reduce the risk of attacks from external vectors, ensuring more secure deployments within our controlled environment.

### **6. Maintenance and Cost Efficiency**

#### **6.1 Maintenance in EKS-Based ADO Agents**
- **Lower Maintenance Overhead:** EKS is a managed service, which reduces the operational burden of maintaining the Kubernetes control plane. AWS handles patching, scaling, and high availability, allowing us to focus on managing the application workloads rather than the infrastructure.
- **Pay-as-You-Go Model:** EKS operates on a pay-per-use model, meaning we only pay for the resources consumed by our agents and applications. However, the cost of network egress (the traffic flowing between cloud services and our on-prem systems) can add up, especially in high-volume environments.

#### **6.2 Maintenance in On-Prem Kubernetes Agents**
- **Higher Maintenance Requirements:** Managing an on-prem Kubernetes cluster requires more hands-on management, including handling software updates, scaling, and infrastructure maintenance. This increases the operational overhead and requires dedicated resources to maintain cluster health.
- **Fixed Costs:** Hosting agents on-premises involves fixed infrastructure costs, including hardware, electricity, and cooling. For stable and predictable workloads, this approach can be more cost-effective over time compared to cloud-based pay-per-use pricing.

### **7. Disaster Recovery and Resilience**

#### **7.1 Disaster Recovery in EKS-Based ADO Agents**
- **Built-In Cloud Resilience:** EKS comes with built-in disaster recovery and resilience features, such as multi-region support, automated backups, and high availability. If an AWS region experiences an outage, EKS can easily shift workloads to another region with minimal disruption.

#### **7.2 Disaster Recovery in On-Prem Kubernetes Agents**
- **Manual Recovery:** On-prem environments typically lack the automated resilience offered by cloud services. Disaster recovery and redundancy must be manually configured and maintained, requiring more effort and planning to ensure uptime and service continuity.

### **8. Advantages and Disadvantages Summary**

| **Aspect**                        | **EKS-Based ADO Agent**                               | **On-Prem Kubernetes Agent**                          |
|-----------------------------------|-------------------------------------------------------|------------------------------------------------------|
| **Traffic Flow**                  | Multi-hop (increased latency)                         | Direct (low latency)                                 |
| **Security**                      | Shared responsibility; multiple hops                  | Full control; reduced attack surface                 |
| **Maintenance**                   | Lower maintenance (cloud-managed)                     | Higher maintenance (self-managed)                    |
| **Cost**                          | Pay-as-you-go, but higher network egress costs        | Fixed infrastructure costs                           |
| **Disaster Recovery**             | Built-in cloud-native resilience                      | Requires manual configuration                        |
| **Latency for On-Prem Deployments**| Higher due to cloud and on-prem interaction           | Minimal, direct traffic flow                         |

### **9. Conclusion**

When deploying on-prem applications, we must carefully evaluate the trade-offs between using ADO agents in EKS versus using on-prem Kubernetes agents. While EKS provides lower maintenance overhead and cloud-native resilience, the multi-hop traffic flow can introduce latency and security complexities for on-prem deployments.

On the other hand, running ADO agents on-prem offers greater control over security, reduced latency, and a more streamlined deployment process, but it comes with higher maintenance costs and operational complexity. The right choice depends on the deployment needs and priorities, whether they are focused on low latency and security, or flexibility and scalability through cloud services.

### **10. Recommendations**

- For **low-latency, highly secure on-prem deployments**, on-prem Kubernetes agents provide a direct, secure, and efficient option that minimizes latency and external dependencies.
- For **scalability and reduced maintenance**, EKS-based ADO agents may be a better fit, but additional considerations need to be made regarding the multi-hop traffic flow and its impact on deployment performance.

By weighing these factors, we can ensure that our deployment pipelines are optimized for both efficiency and security, regardless of the environment in which our applications are deployed.

---
