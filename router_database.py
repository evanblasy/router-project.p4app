

class RouterDatabase:
	def __init__(self, source_ip):
		self.topology = Graph(1)
		self.source_ip = source_ip
		self.routers = [source_ip]

	def add_link(self, ip_one, ip_two):
		if ip_one not in self.routers:
			self.add_router(ip_one)
		if ip_two not in self.routers:
			self.add_router(ip_two)
		self.topology.addEdge(self.routers.index(ip_one),
												self.routers.index(ip_two))

	def add_router(self, ip):
		self.topology.addVertex()
		self.routers.append(ip)

	def remove_router(self, ip):
		index = self.routers.index(ip)
		self.routers.pop(ip)
		self.topology.removeVertex(index)

	def remove_link(self, ip_one, ip_two):
		if ip_one not in self.routers or ip_two not in self.routers:
			print("LINK NOT IN GRAPH")
			return
		self.topology.removeEdge(self.routers.index(ip_one),
												self.routers.index(ip_two))


	def compute_first_jumps(self):
		parents = self.topology.dijkstra(0)
		jumps = {}
		for i in range(1,len(self.routers)):
			prev = i
			while parents[parents[prev]] != -1:
				prev = parents[prev]
			jumps[self.routers[i]] = [self.source_ip, self.routers[prev]]
		return jumps


class Graph:
	# number of vertices
	__n = 0

	# adjacency matrix
	__g = [[0 for x in range(10)] for y in range(10)]

	# constructor
	def __init__(self, x):
		self.__n = x

		# initializing each element of the adjacency matrix to zero
		for i in range(0, self.__n):
			for j in range(0, self.__n):
				self.__g[i][j] = 0

	def displayAdjacencyMatrix(self): 
		print("\n\n Adjacency Matrix:", end ="") 

		# displaying the 2D array 
		for i in range(0, self.__n): 
			print() 
			for j in range(0, self.__n): 
				print("", self.__g[i][j], end ="") 
		
	def addEdge(self, x, y): 
 
		# checks if the vertex exists in the graph  
		if(x>= self.__n) or (y >= self.__n): 
			print("Vertex does not exists !") 
					
		# checks if the vertex is connecting to itself 
		if(x == y): 
			print("Same Vertex !") 
		else: 
							 
			# connecting the vertices 
			self.__g[y][x]= 1
			self.__g[x][y]= 1

	def removeEdge(self, x, y):
		if(x>= self.__n) or (y >= self.__n): 
			print("Vertex does not exists !") 
					
		# checks if the vertex is connecting to itself 
		if(x == y): 
			print("Same Vertex !") 
		else: 
							 
			# disconnect the vertices 
			self.__g[y][x]= 0
			self.__g[x][y]= 0
		
	def addVertex(self): 
					 
		# increasing the number of vertices 
		self.__n = self.__n + 1
					 
		# initializing the new elements to 0  
		for i in range(0, self.__n): 
			self.__g[i][self.__n-1]= 0
			self.__g[self.__n-1][i]= 0

	def removeVertex(self, x): 
					
			# checking if the vertex is present 
		if(x>=self.__n): 
			print("Vertex not present !") 
		else: 
			
			# removing the vertex 
			while(x<self.__n): 
		
				# shifting the rows to left side  
				for i in range(0, self.__n): 
					self.__g[i][x]= self.__g[i][x + 1] 
				
				# shifting the columns upwards 
				for i in range(0, self.__n): 
					self.__g[x][i]= self.__g[x + 1][i] 
				x = x + 1

			# decreasing the number of vertices 
			self.__n = self.__n - 1

	def minDistance(self,dist,queue): 
		# Initialize min value and min_index as -1 
		minimum = float("Inf") 
		min_index = -1
			
		# from the dist array,pick one which 
		# has min value and is till in queue 
		for i in range(len(dist)): 
			# print("index: " + str(i) + " distance: " + str(dist[i]))
			if dist[i] < minimum and i in queue:
				minimum = dist[i] 
				min_index = i 
		return min_index 

	def printPath(self, parent, j): 

		#Base Case : If j is source 
		if parent[j] == -1 :  
			print(j) 
			return
		self.printPath(parent , parent[j]) 
		print(j, end="")


	# A utility function to print 
	# the constructed distance 
	# array 
	def printSolution(self, dist, parent): 
		src = 0
		print("Vertex \t\tDistance from Source\tPath") 
		for i in range(1, len(dist)): 
			print("\n%d --> %d \t\t%d \t\t\t\t\t" % (src, i, dist[i])), 
		self.printPath(parent,i) 

	def dijkstra(self, src): 

		row = self.__n
		col = self.__n

		# The output array. dist[i] will hold 
		# the shortest distance from src to i 
		# Initialize all distances as INFINITE  
		dist = [float("Inf")] * row 

		# Parent array to store  
		# shortest path tree 
		parent = [-1] * row 

		# Distance of source vertex  
		# from itself is always 0 
		dist[src] = 0
	
		# Add all vertices in queue 
		queue = [] 
		for i in range(row): 
			queue.append(i) 
					
		# Find shortest path for all vertices 
		while queue: 

			# Pick the minimum dist vertex  
			# from the set of vertices 
			# still in queue 
			u = self.minDistance(dist,queue)  

			# remove min element      
			queue.remove(u)

			# Update dist value and parent  
			# index of the adjacent vertices of 
			# the picked vertex. Consider only  
			# those vertices which are still in 
			# queue 
			for i in range(col): 
				'''Update dist[i] only if it is in queue, there is 
				an edge from u to i, and total weight of path from 
				src to i through u is smaller than current value of 
				dist[i]'''
				if self.__g[u][i] and i in queue: 
					if dist[u] + self.__g[u][i] < dist[i]: 
						dist[i] = dist[u] + self.__g[u][i] 
						parent[i] = u 

		# print the constructed distance array 
		# print(dist)
		# self.printSolution(dist, parent)
		return parent
