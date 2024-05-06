import subprocess

def create_container(image, ports, name):
    subprocess.run(["docker", "run", "-d", "--name", name, "-p", f"{ports[0]}:{ports[1]}", image])
    print(f"Container {name} created from image {image}")

if __name__ == "__main__":
    # Define the services with their respective images and ports
    services = [
        {"name": "druid", "image": "vulhub/apache-druid:0.20.0", "ports": ["8888", "8888/tcp"]},
        {"name": "webmin", "image": "vulhub/webmin:1.910", "ports": ["10000", "10000/tcp"]}
    ]

    # Create containers for each service
    for service in services:
        print(f"Creating container for service {service['name']}...")
        create_container(service['image'], service['ports'], service['name'])

    print("All containers created successfully.")

    # List active containers
    print("Listing active containers:")
    subprocess.run(["docker", "ps"])
